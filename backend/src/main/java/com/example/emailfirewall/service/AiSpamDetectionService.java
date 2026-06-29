package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AiSpamResult;
import com.example.emailfirewall.dto.ParsedEmail;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AiSpamDetectionService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${ollama.url:http://localhost:11434/api/generate}")
    private String ollamaUrl;

    @Value("${ollama.model:qwen2.5:1.5b}")
    private String model;

    public AiSpamResult analyze(ParsedEmail email) {
        if (email == null) {
            return new AiSpamResult(0, "UNKNOWN", "LOW", List.of(), "No email content");
        }

        String prompt = buildPrompt(email);

        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(5000);
        factory.setReadTimeout(30000);

        RestClient client = RestClient.builder()
                .requestFactory(factory)
                .build();

        Map<String, Object> body = Map.of(
                "model", model,
                "prompt", prompt,
                "stream", false,
                "format", "json",
                "options", Map.of(
                        "temperature", 0,
                        "num_ctx", 1024,
                        "num_predict", 200
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

            JsonNode json = objectMapper.readTree(text);

            String classification =
                    json.path("classification")
                            .asText("UNKNOWN")
                            .toUpperCase();

            int score =
                    json.path("spamScore")
                            .asInt(0);

            score = normalizeAiScore(classification, score);

            return new AiSpamResult(
                    score,
                    classification,
                    json.path("confidence").asText("LOW"),
                    objectMapper.convertValue(
                            json.path("reasons"),
                            objectMapper.getTypeFactory()
                                    .constructCollectionType(List.class, String.class)
                    ),
                    json.path("explanation").asText("")
            );

        } catch (Exception e) {
            e.printStackTrace();
            return fallbackAnalyze(email, e);
        }
    }
    private int normalizeAiScore(String classification, int score) {
        if (classification == null) return 0;

        classification = classification.toUpperCase();

        return switch (classification) {
            case "BENIGN" -> clamp(score, 0, 10);
            case "MARKETING" -> clamp(score, 5, 20);
            case "SPAM" -> clamp(score, 30, 50);
            case "SCAM" -> clamp(score, 60, 80);
            case "PHISHING" -> clamp(score, 80, 100);
            case "MALWARE" -> clamp(score, 90, 100);
            case "UNKNOWN" -> 0;
            default -> 0;
        };
    }

    private int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
    private AiSpamResult fallbackAnalyze(ParsedEmail email, Exception e) {
        String text = (
                safe(email.from) + " " +
                        safe(email.subject) + " " +
                        safe(email.bodyText)
        ).toLowerCase();

        int score = 0;
        List<String> reasons = new java.util.ArrayList<>();

        if (text.contains("felicitari")
                || text.contains("ai castigat")
                || text.contains("premiu")
                || text.contains("voucher")) {
            score += 35;
            reasons.add("Prize/giveaway language detected");
        }

        if (text.contains("urgent")
                || text.contains("expira")
                || text.contains("30 de minute")
                || text.contains("imediat")) {
            score += 20;
            reasons.add("Urgency pressure detected");
        }

        if (text.contains("datele cardului")
                || text.contains("cardului")
                || text.contains("parola")
                || text.contains("password")
                || text.contains("login")) {
            score += 35;
            reasons.add("Sensitive information or login request detected");
        }

        if (text.contains("verificare")
                || text.contains("verify")
                || text.contains("account")) {
            score += 15;
            reasons.add("Account verification wording detected");
        }

        if (text.contains("factura")
                || text.contains("invoice")
                || text.contains("plata")
                || text.contains("payment")
                || text.contains("restanta")
                || text.contains("overdue")) {
            score += 30;
            reasons.add("Payment or invoice request detected");
        }

        score = Math.min(score, 100);

        String classification =
                score >= 80 ? "PHISHING" :
                        score >= 60 ? "SCAM" :
                                score >= 40 ? "SPAM" :
                                        "UNKNOWN";
        score = normalizeAiScore(classification, score);
        return new AiSpamResult(
                score,
                classification,
                "MEDIUM",
                reasons,
                "Local LLM unavailable or invalid response. Fallback classifier used. Cause: "
                        + e.getClass().getSimpleName()
        );
    }

    private String buildPrompt(ParsedEmail email) {
        String textBody = truncate(safe(email.bodyText), 800);

        return """
            You are an email security classifier.

            Classify the email as exactly one of:
            BENIGN, MARKETING, SPAM, PHISHING, SCAM, MALWARE, UNKNOWN.

            Classification rules:
            - BENIGN = legitimate personal or business communication.
            - MARKETING = legitimate newsletters, promotions, ecommerce campaigns, job alerts, or brand offers.
            - SPAM = unsolicited bulk messages or aggressive advertising.
            - PHISHING = credential theft, fake login pages, impersonation, account verification, passwords, card data, or personal data requests.
            - SCAM = fraud, fake rewards, payment manipulation, overdue invoice pressure, bank transfer requests, urgency attacks.
            - MALWARE = suspicious executable or malicious attachment/link delivery.
            - UNKNOWN = insufficient content or unclear intent. Use UNKNOWN only if no better class applies.

            Scoring guide:
            - 0-20: benign, marketing, normal automated notification, or insufficient evidence
            - 21-40: mildly suspicious marketing/spam
            - 41-60: spam or suspicious promotion
            - 61-80: scam or phishing indicators
            - 81-100: strong phishing, malware, credential theft, card/payment request, or urgent fraud

            Important:
            - Normal newsletters, ecommerce promotions, job alerts, and brand offers must be MARKETING, not PHISHING.
            - Payment requests, unpaid invoices, overdue balances, bank transfers, and payment confirmations increase spamScore significantly.
            - Prize/reward claims, unrealistic offers, urgency, pressure tactics, login/password/card requests increase spamScore.
            - Return ONLY valid JSON. No markdown. No extra text.

            Required JSON schema:
            {
              "spamScore": 0,
              "classification": "BENIGN",
              "confidence": "LOW",
              "reasons": [],
              "explanation": ""
            }

            Email:
            From: %s
            Subject: %s
            Body:
            %s
            """.formatted(
                safe(email.from),
                safe(email.subject),
                textBody
        );
    }

    private String safe(String s) {
        return s == null ? "" : s;
    }

    private String truncate(String s, int max) {
        if (s.length() <= max) return s;
        return s.substring(0, max);
    }
}