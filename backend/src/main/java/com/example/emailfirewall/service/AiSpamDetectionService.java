package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AiSpamResult;
import com.example.emailfirewall.dto.ParsedEmail;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class AiSpamDetectionService {

    private final ObjectMapper objectMapper;
    private final RestClient client;

    @Value("${ollama.url:http://localhost:11434/api/generate}")
    private String ollamaUrl;

    @Value("${ollama.model:qwen2.5:1.5b}")
    private String model;

    public AiSpamDetectionService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(30000);

        this.client = RestClient.builder()
                .requestFactory(factory)
                .build();
    }

    public AiSpamResult analyze(ParsedEmail email) {
        if (email == null) {
            return new AiSpamResult(0, "UNKNOWN", "LOW", List.of(), "No email content");
        }

        if (isTrustedSender(email.from)) {
            return new AiSpamResult(
                    0,
                    "BENIGN",
                    "HIGH",
                    List.of("Trusted sender domain"),
                    "The sender belongs to a known legitimate domain"
            );
        }

        AiSpamResult localResult = localRuleAnalyze(email);

        if (!isAmbiguous(localResult)) {
            log.info("Local spam rules were enough: classification={} score={}",
                    localResult.classification(), localResult.spamScore());
            return localResult;
        }

        String prompt = buildPrompt(email);

        Map<String, Object> body = Map.of(
                "model", model,
                "prompt", prompt,
                "stream", false,
                "format", "json",
                "options", Map.of(
                        "temperature", 0,
                        "num_ctx", 4096,
                        "num_predict", 300
                )
        );

        try {
            String response = client.post()
                    .uri(ollamaUrl)
                    .body(body)
                    .retrieve()
                    .body(String.class);

            JsonNode root = objectMapper.readTree(response);
            String text = root.path("response").asText();

            if (text == null || text.isBlank()) {
                return localResult;
            }

            JsonNode json = objectMapper.readTree(text);

            String classification = normalizeClassification(
                    json.path("classification").asText("UNKNOWN")
            );

            int score = normalizeAiScore(
                    classification,
                    json.path("spamScore").asInt(0)
            );

            String confidence = normalizeConfidence(
                    json.path("confidence").asText("LOW")
            );

            return new AiSpamResult(
                    score,
                    classification,
                    confidence,
                    readReasons(json),
                    json.path("explanation").asText("")
            );

        } catch (Exception e) {
            log.warn("LLM unavailable or invalid response. Using local rule result.", e);
            return localResult;
        }
    }

    private AiSpamResult localRuleAnalyze(ParsedEmail email) {
        String text = (
                safe(email.from) + " " +
                        safe(email.subject) + " " +
                        safe(email.bodyText)
        ).toLowerCase();

        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (containsAny(text, "felicitari", "felicitări", "ai castigat", "ai câștigat",
                "premiu", "voucher", "cadou gratuit")) {
            score += 35;
            reasons.add("Prize or giveaway language detected");
        }

        if (containsAny(text, "urgent", "expira", "expiră", "30 de minute",
                "imediat", "ultimul avertisment")) {
            score += 20;
            reasons.add("Urgency pressure detected");
        }

        if (containsAny(text, "datele cardului", "cardului", "parola", "parolă",
                "password", "login", "autentificare", "cod otp", "cod de verificare")) {
            score += 35;
            reasons.add("Sensitive information or login request detected");
        }

        if (containsAny(text, "contul tau", "contul tău", "suspendat",
                "restrictionat", "restricționat")) {
            score += 15;
            reasons.add("Account restriction wording detected");
        }

        if (containsAny(text, "factura", "factură", "invoice", "plata", "plată",
                "payment", "restanta", "restanță", "overdue", "transfer bancar", "iban")) {
            score += 30;
            reasons.add("Payment or invoice request detected");
        }

        if (containsAny(text, ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs")) {
            score += 40;
            reasons.add("Risky executable file reference detected");
        }

        score = Math.min(score, 100);

        String classification =
                score >= 90 ? "MALWARE" :
                        score >= 80 ? "PHISHING" :
                                score >= 60 ? "SCAM" :
                                        score >= 40 ? "SPAM" :
                                                "BENIGN";

        score = normalizeAiScore(classification, score);

        return new AiSpamResult(
                score,
                classification,
                score >= 60 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW",
                reasons,
                "Local rule-based spam analysis"
        );
    }

    private boolean isAmbiguous(AiSpamResult result) {
        if (result == null) return true;

        int score = result.spamScore() != null ? result.spamScore() : 0;
        String classification = result.classification();

        if ("BENIGN".equalsIgnoreCase(classification)) return false;
        if (score >= 60) return false;

        return score >= 20;
    }

    private boolean isTrustedSender(String sender) {
        if (sender == null) return false;

        String s = sender.toLowerCase();

        return s.endsWith("@google.com")
                || s.endsWith("@accounts.google.com")
                || s.endsWith("@forms-receipts-noreply@google.com")
                || s.endsWith("@facebookmail.com")
                || s.endsWith("@linkedin.com")
                || s.endsWith("@github.com")
                || s.endsWith("@amazon.com");
    }

    private String normalizeClassification(String value) {
        if (value == null) return "UNKNOWN";

        return switch (value.trim().toUpperCase()) {
            case "BENIGN", "MARKETING", "SPAM", "PHISHING", "SCAM", "MALWARE", "UNKNOWN" ->
                    value.trim().toUpperCase();
            default -> "UNKNOWN";
        };
    }

    private String normalizeConfidence(String value) {
        if (value == null) return "LOW";

        return switch (value.trim().toUpperCase()) {
            case "LOW", "MEDIUM", "HIGH" -> value.trim().toUpperCase();
            default -> "LOW";
        };
    }

    private int normalizeAiScore(String classification, int score) {
        if (classification == null) return 0;

        return switch (classification.toUpperCase()) {
            case "BENIGN" -> clamp(score, 0, 10);
            case "MARKETING" -> clamp(score, 5, 20);
            case "SPAM" -> clamp(score, 30, 50);
            case "SCAM" -> clamp(score, 40, 70);
            case "PHISHING" -> clamp(score, 55, 85);
            case "MALWARE" -> clamp(score, 80, 100);
            case "UNKNOWN" -> 0;
            default -> 0;
        };
    }

    private List<String> readReasons(JsonNode json) {
        JsonNode reasonsNode = json.path("reasons");

        if (!reasonsNode.isArray()) {
            return List.of();
        }

        return objectMapper.convertValue(
                reasonsNode,
                objectMapper.getTypeFactory()
                        .constructCollectionType(List.class, String.class)
        );
    }

    private String buildPrompt(ParsedEmail email) {
        String textBody = truncate(safe(email.bodyText), 1500);

        return """
            Classify this email as one of:
            BENIGN, MARKETING, SPAM, PHISHING, SCAM, MALWARE, UNKNOWN.

            Romanian and English emails are supported.

            Important:
            - Legitimate security alerts from trusted providers such as Google, Microsoft, GitHub,
              Facebook, LinkedIn, Amazon, banks, or universities should be BENIGN unless there is
              clear impersonation, credential theft, malicious link, or payment fraud.
            - Do not classify a normal security notification as SCAM only because it mentions account,
              login, verification, or security.
            - PHISHING means credential theft, fake login pages, password/card/OTP/personal data request.
            - SCAM means fake prize, fraud, payment pressure, bank transfer manipulation.
            - MARKETING means legitimate promotion/newsletter/job alert.
            - BENIGN means normal personal, business, service, or security notification.

            Return only JSON:
            {
              "spamScore": 0,
              "classification": "BENIGN",
              "confidence": "LOW",
              "reasons": ["reason1","reason2"],
              "explanation": "short explanation"
            }

            Email:
            From: %s
            Subject: %s
            Body: %s
            """.formatted(
                safe(email.from),
                safe(email.subject),
                textBody
        );
    }

    private boolean containsAny(String text, String... keywords) {
        for (String keyword : keywords) {
            if (text.contains(keyword)) return true;
        }
        return false;
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private String safe(String s) {
        return s == null ? "" : s;
    }

    private String truncate(String s, int max) {
        if (s.length() <= max) return s;
        return s.substring(0, max);
    }
}