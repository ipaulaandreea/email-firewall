package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AiSpamResult;
import com.example.emailfirewall.dto.ParsedEmail;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${ollama.model:mistral:7b}")
    private String model;

    public AiSpamResult analyze(ParsedEmail email) {
        if (email == null) {
            return new AiSpamResult(0, "UNKNOWN", "LOW", List.of(), "No email content");
        }

        String prompt = buildPrompt(email);

        RestClient client = RestClient.builder().build();

        Map<String, Object> body = Map.of(
                "model", model,
                "prompt", prompt,
                "stream", false,
                "format", "json",
                "options", Map.of(
                        "temperature", 0
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

            return new AiSpamResult(
                    json.path("spamScore").asInt(0),
                    json.path("classification").asText("UNKNOWN"),
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

    private AiSpamResult fallbackAnalyze(ParsedEmail email, Exception e) {
        String text = (
                safe(email.from) + " " +
                        safe(email.subject) + " " +
                        safe(email.bodyText) + " " +
                        safe(email.bodyHtml)
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

        score = Math.min(score, 100);

        String classification =
                score >= 80 ? "PHISHING" :
                        score >= 60 ? "SCAM" :
                                score >= 40 ? "SPAM" :
                                        "UNKNOWN";

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
        return """
                You are an email security classifier used inside an email firewall.

                Classify the email as exactly one of:
                BENIGN, MARKETING, SPAM, PHISHING, SCAM, MALWARE, UNKNOWN.

                Rules:
                - Prize winning, reward claims, urgent rewards, requests for card data, passwords, login verification, or personal data are suspicious.
                - If the email asks for card data, password, login, account verification, or sensitive personal information, classify as PHISHING or SCAM.
                - If the email uses urgency, unrealistic rewards, or pressure tactics, increase spamScore.
                - Return ONLY valid JSON.
                - Do not write markdown.
                - Do not write explanations outside JSON.
                - Your response must start with { and end with }.

                JSON schema:
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

                Text body:
                %s

                HTML body:
                %s
                """.formatted(
                safe(email.from),
                safe(email.subject),
                truncate(safe(email.bodyText), 4000),
                truncate(safe(email.bodyHtml), 4000)
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