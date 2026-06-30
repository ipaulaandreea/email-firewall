package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.*;
import com.example.emailfirewall.entity.*;
import com.example.emailfirewall.enums.*;
import com.example.emailfirewall.repository.EmailRepository;
import com.example.emailfirewall.repository.RuleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.HtmlUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final EmailRepository emailRepository;
    private final RuleEvaluationService ruleEvaluationService;
    private final EmailAuthService emailAuthService;
    private final UrlAnalysisService urlAnalysisService;
    private final AttachmentAnalysisService attachmentAnalysisService;
    private final AiSpamDetectionService aiSpamDetectionService;

    public IngestResponse ingestJson(IngestEmailRequest req) {
        ParsedEmail p = new ParsedEmail();

        p.from = req.from();
        if (req.to() != null) p.to.addAll(req.to());
        p.subject = req.subject();
        p.bodyText = req.bodyText();
        p.bodyHtml = req.bodyHtml();

        if (req.headers() != null) {
            req.headers().forEach((k, v) -> p.headers.put(k, List.of(v)));
        }

        return ingestParsedEmail(p, IngestSource.JSON_API);
    }

    @Transactional
    public IngestResponse ingestParsedEmail(ParsedEmail p, IngestSource source) {
        if (p == null) p = new ParsedEmail();

        String username = currentUsername();
        String dedupeKey = username + ":" + buildDedupeKey(p);

        Optional<EmailEntity> existing = emailRepository.findByDedupeKey(dedupeKey);
        if (existing.isPresent()) {
            return buildIngestResponse(existing.get());
        }

        EmailEntity email = new EmailEntity();
        email.setId(UUID.randomUUID());
        email.setDedupeKey(dedupeKey);
        email.setIngestSource(source);
        email.setFromAddress(p.from != null ? p.from : "unknown");
        email.setFromDomain(extractDomain(p.from));
        email.setSubject(p.subject);
        email.setBodyText(p.bodyText);
        email.setBodyHtmlSanitized(p.bodyHtml != null ? HtmlUtils.htmlEscape(p.bodyHtml) : null);
        email.setSizeBytes(p.rawEml != null ? (long) p.rawEml.length : null);

        ensureCollections(email);

        if (p.to != null) {
            email.getToAddresses().addAll(p.to);
        }

        RuleEvaluationResult eval = ruleEvaluationService.evaluate(p);
        if (eval == null) eval = new RuleEvaluationResult();

        EmailAuthEvaluation auth = safeAuthEvaluate(p);
        int authScore = authScore(auth);

        int extraScore = 0;

        FirewallScanResult urlResult = urlAnalysisService.analyze(p);
        extraScore += extraSecurityScore(urlResult);
        persistLinks(email, urlResult);

        FirewallScanResult attachmentResult = attachmentAnalysisService.analyze(p);
        extraScore += extraSecurityScore(attachmentResult);
        persistAttachments(email, p);
        System.out.println("RULE SCORE = " + eval.getTotalScore());
        System.out.println("AUTH SCORE = " + authScore);
        System.out.println("URL SCORE = " + extraSecurityScore(urlResult));
        System.out.println("ATTACHMENT SCORE = " + extraSecurityScore(attachmentResult));
        int score = eval.getTotalScore() + authScore + extraScore;
        score = Math.min(score, 100);
        EmailVerdict forcedVerdict =
                eval.isBypassTriggered() ? null : eval.getForcedVerdict();

        EmailVerdict verdict = determineVerdict(score, forcedVerdict);

        email.setOwnerUsername(username);
        email.setThreatScore(score);
        email.setVerdict(verdict);
        email.setStatus(EmailStatus.ANALYZED);
        persistRuleHits(email, eval);
        persistAuthResults(email, auth);

        EmailEntity saved = emailRepository.save(email);
        return buildIngestResponse(saved);
    }

    private String currentUsername() {
        var auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth.getName() == null || auth.getName().isBlank()) {
            return "anonymous";
        }

        return auth.getName();
    }

    @Transactional
    public IngestResponse analyzeSpam(UUID emailId) {
        EmailEntity email = emailRepository.findById(emailId)
                .orElseThrow(() -> new IllegalArgumentException("Email not found: " + emailId));

        ParsedEmail parsed = new ParsedEmail();
        parsed.from = email.getFromAddress();
        parsed.subject = email.getSubject();
        parsed.bodyText = email.getBodyText();
        parsed.bodyHtml = null;

        AiSpamResult ai = aiSpamDetectionService.analyze(parsed);

        int currentScore = email.getThreatScore() != null ? email.getThreatScore() : 0;
        int previousAiScore = email.getAiSpamScore() != null ? email.getAiSpamScore() : 0;

        int baseScoreWithoutAi = Math.max(0, currentScore - previousAiScore);

        int aiRawScore = ai.spamScore() != null ? ai.spamScore() : 0;
        int aiPartialScore = calculateAiContribution(aiRawScore);

        int newScore = baseScoreWithoutAi + aiPartialScore;

        email.setAiSpamScore(aiPartialScore);
        email.setAiClassification(ai.classification());
        email.setAiExplanation(ai.explanation());

        email.setThreatScore(newScore);
        email.setVerdict(determineVerdict(newScore, null));

        EmailEntity saved = emailRepository.save(email);
        return buildIngestResponse(saved);
    }

    private IngestResponse buildIngestResponse(EmailEntity email) {
        return new IngestResponse(
                email.getId(),
                email.getThreatScore(),
                email.getVerdict(),
                email.getStatus()
        );
    }

    private int calculateAiContribution(Integer aiScore) {
        if (aiScore == null) return 0;
        if (aiScore >= 80) return 40;
        if (aiScore >= 60) return 25;
        if (aiScore >= 40) return 10;
        return 0;
    }

    private EmailAuthEvaluation safeAuthEvaluate(ParsedEmail p) {
        try {
            return emailAuthService.evaluate(p);
        } catch (Exception e) {
            return null;
        }
    }

    private int extraSecurityScore(FirewallScanResult result) {
        if (result == null) return 0;
        return Math.max(0, result.getScore());
    }

    private void persistAttachments(EmailEntity email, ParsedEmail p) {
        if (email == null || p == null || p.attachments == null) return;

        if (email.getAttachments() == null) {
            email.setAttachments(new ArrayList<>());
        }

        for (AttachmentMeta a : p.attachments) {
            if (a == null) continue;

            EmailAttachmentEntity entity = new EmailAttachmentEntity();
            entity.setEmail(email);
            entity.setFilename(a.filename);
            entity.setContentType(a.contentType);
            entity.setSizeBytes(a.size);
            entity.setSha256(a.sha256);
            entity.setExtension(attachmentAnalysisService.extension(a.filename != null ? a.filename : ""));
            entity.setVerdict(attachmentAnalysisService.verdictFor(a));

            email.getAttachments().add(entity);
        }
    }

    private void persistLinks(EmailEntity email, FirewallScanResult result) {
        if (email == null || result == null || result.getLinks() == null) return;

        if (email.getLinks() == null) {
            email.setLinks(new ArrayList<>());
        }

        for (ScannedLink scanned : result.getLinks()) {
            if (scanned == null) continue;

            EmailLinkEntity link = new EmailLinkEntity();
            link.setEmail(email);
            link.setUrlRaw(scanned.urlRaw);
            link.setUrlNormalized(scanned.urlNormalized);
            link.setHost(scanned.host);
            link.setShortener(scanned.shortener);
            link.setVerdict(scanned.verdict);

            if (link.getSignals() == null) {
                link.setSignals(new ArrayList<>());
            }

            if (scanned.signals != null) {
                for (FirewallFinding f : scanned.signals) {
                    LinkSignalEntity signal = new LinkSignalEntity();
                    signal.setLink(link);
                    signal.setSignalType(f.code());
                    signal.setSeverity(severity(f.scoreDelta()));
                    signal.setScoreDelta(f.scoreDelta());
                    signal.setDetails(f.message());

                    link.getSignals().add(signal);
                }
            }

            email.getLinks().add(link);
        }
    }

    private void persistRuleHits(EmailEntity email, RuleEvaluationResult eval) {
        if (email == null || eval == null || eval.getHits() == null) {
            return;
        }

        if (email.getRuleHits() == null) {
            email.setRuleHits(new ArrayList<>());
        }

        for (RuleEvaluationResult.RuleHit hit : eval.getHits()) {
            if (hit == null || hit.rule() == null) continue;

            RuleHitEntity e = new RuleHitEntity();
            e.setEmail(email);
            e.setRule(hit.rule());
            e.setScoreDelta(hit.scoreDelta());
            e.setForcedVerdict(hit.forcedVerdict());
            e.setMessage(hit.message());

            email.getRuleHits().add(e);
        }
    }

    private void persistAuthResults(EmailEntity email, EmailAuthEvaluation auth) {
        if (email == null || auth == null) return;

        AuthResultsEntity authEntity = new AuthResultsEntity();
        authEntity.setEmail(email);
        authEntity.setSpfResult(auth.spfResult);
        authEntity.setDkimResult(auth.dkimResult);
        authEntity.setDmarcResult(auth.dmarcResult);
        authEntity.setDmarcPolicy(auth.dmarcPolicy);
        authEntity.setDetailsJson(AuthResultsJsonBuilder.build(auth));

        email.setAuthResults(authEntity);
    }

    private int authScore(EmailAuthEvaluation auth) {
        if (auth == null) return 0;

        int score = 0;

        if (auth.spfResult == SpfResult.FAIL) score += 15;
        else if (auth.spfResult == SpfResult.SOFTFAIL) score += 8;

        if (auth.dkimResult == DkimResult.FAIL) score += 15;

        if (auth.dmarcResult == DmarcResult.FAIL) {
            score += switch (auth.dmarcPolicy) {
                case REJECT -> 40;
                case QUARANTINE -> 30;
                case NONE, UNKNOWN -> 20;
            };
        }

        return score;
    }

    private void ensureCollections(EmailEntity email) {
        if (email.getToAddresses() == null) email.setToAddresses(new ArrayList<>());
        if (email.getRuleHits() == null) email.setRuleHits(new ArrayList<>());
        if (email.getHeaders() == null) email.setHeaders(new ArrayList<>());
        if (email.getAttachments() == null) email.setAttachments(new ArrayList<>());
        if (email.getLinks() == null) email.setLinks(new ArrayList<>());
    }

    private EmailVerdict determineVerdict(int score, EmailVerdict forced) {
        if (forced != null) return forced;
        if (score >= 70) return EmailVerdict.BLOCK;
        if (score >= 30) return EmailVerdict.QUARANTINE;
        return EmailVerdict.ALLOW;
    }

    private String severity(int score) {
        if (score >= 40) return "HIGH";
        if (score >= 20) return "MEDIUM";
        return "LOW";
    }

    private String extractDomain(String email) {
        if (email == null) return null;
        int at = email.lastIndexOf('@');
        if (at < 0 || at == email.length() - 1) return null;
        return email.substring(at + 1).replace(">", "").trim().toLowerCase();
    }

    private String buildDedupeKey(ParsedEmail parsed) {
        String raw =
                safe(parsed != null ? parsed.from : null) + "|" +
                        safe(parsed != null ? parsed.subject : null) + "|" +
                        safe(parsed != null ? parsed.bodyText : null) + "|" +
                        safe(parsed != null ? parsed.bodyHtml : null);

        return sha256(raw.toLowerCase());
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private String safe(String s) {
        return s == null ? "" : s.trim();
    }

    static class AuthResultsJsonBuilder {
        static String build(EmailAuthEvaluation a) {
            if (a == null) return null;

            StringBuilder sb = new StringBuilder();
            sb.append('{');

            sb.append("\"spf\":{");
            sb.append("\"result\":\"").append(a.spfResult).append("\"");
            if (a.spfDomain != null) sb.append(",\"domain\":\"").append(escape(a.spfDomain)).append("\"");
            if (a.spfSummary != null) sb.append(",\"summary\":\"").append(escape(a.spfSummary)).append("\"");
            sb.append("},");

            sb.append("\"dkim\":{");
            sb.append("\"result\":\"").append(a.dkimResult).append("\"");
            if (a.dkimSummary != null) sb.append(",\"summary\":\"").append(escape(a.dkimSummary)).append("\"");
            sb.append(",\"signatures\":[");

            if (a.dkimSignatures != null) {
                for (int i = 0; i < a.dkimSignatures.size(); i++) {
                    var s = a.dkimSignatures.get(i);
                    if (i > 0) sb.append(',');
                    sb.append('{');
                    if (s.domain != null) sb.append("\"domain\":\"").append(escape(s.domain)).append("\",");
                    if (s.selector != null) sb.append("\"selector\":\"").append(escape(s.selector)).append("\",");
                    sb.append("\"result\":\"").append(s.result).append("\"");
                    if (s.summary != null) sb.append(",\"summary\":\"").append(escape(s.summary)).append("\"");
                    sb.append('}');
                }
            }

            sb.append("]},");

            sb.append("\"dmarc\":{");
            sb.append("\"result\":\"").append(a.dmarcResult).append("\",");
            sb.append("\"policy\":\"").append(a.dmarcPolicy).append("\"");
            if (a.dmarcSpfAligned != null) sb.append(",\"spfAligned\":").append(a.dmarcSpfAligned);
            if (a.dmarcDkimAligned != null) sb.append(",\"dkimAligned\":").append(a.dmarcDkimAligned);
            if (a.dmarcSummary != null) sb.append(",\"summary\":\"").append(escape(a.dmarcSummary)).append("\"");
            sb.append('}');

            sb.append('}');
            return sb.toString();
        }

        private static String escape(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r");
        }
    }
}