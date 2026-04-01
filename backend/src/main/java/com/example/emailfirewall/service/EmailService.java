package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.EmailAuthEvaluation;
import com.example.emailfirewall.dto.IngestEmailRequest;
import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.entity.AuthResultsEntity;
import com.example.emailfirewall.entity.EmailEntity;
import com.example.emailfirewall.entity.RuleEntity;
import com.example.emailfirewall.entity.RuleHitEntity;
import com.example.emailfirewall.enums.*;
import com.example.emailfirewall.repository.EmailRepository;
import com.example.emailfirewall.repository.RuleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final EmailRepository emailRepository;
    private final RuleEvaluationService ruleEvaluationService;
    private final EmailAuthService emailAuthService;
    private final RuleRepository ruleRepository;

    public IngestResponse ingestJson(IngestEmailRequest req) {
        ParsedEmail p = new ParsedEmail();
        p.from = req.from();
        if (req.to() != null) p.to.addAll(req.to());
        p.subject = req.subject();
        p.bodyText = req.bodyText();
        p.bodyHtml = req.bodyHtml();
        if (req.headers() != null) {
            req.headers().forEach((k, v)->
                p.headers.put(k, List.of(v))
            );
        }

        return ingestParsedEmail(p, IngestSource.JSON_API);
    }

    public IngestResponse ingestParsedEmail(ParsedEmail p, IngestSource source) {
        EmailEntity email = new EmailEntity();
        email.setId(UUID.randomUUID());
        email.setIngestSource(source);

        email.setFromAddress(p.from != null ? p.from : "unknown");
        email.setSubject(p.subject);
        email.setBodyText(p.bodyText);
        email.setBodyHtmlSanitized(p.bodyHtml != null ? HtmlUtils.htmlEscape(p.bodyHtml) : null);

        if (p.to != null) email.getToAddresses().addAll(p.to);

        EmailAuthEvaluation auth = emailAuthService.evaluate(p);

        RuleEvaluationResult eval = ruleEvaluationService.evaluate(p);

        applyAuthScoring(eval, auth);

        int score = eval.getTotalScore();
        EmailVerdict verdict = determineVerdict(score, eval.getForcedVerdict());

        email.setThreatScore(score);
        email.setVerdict(verdict);
        email.setStatus(verdict == EmailVerdict.QUARANTINE ? EmailStatus.QUARANTINED : EmailStatus.ANALYZED);

        persistRuleHits(email, eval);

        AuthResultsEntity authEntity = new AuthResultsEntity();
        authEntity.setEmail(email);
        authEntity.setSpfResult(auth.spfResult);
        authEntity.setDkimResult(auth.dkimResult);
        authEntity.setDmarcResult(auth.dmarcResult);
        authEntity.setDmarcPolicy(auth.dmarcPolicy);
        authEntity.setDetailsJson(AuthResultsJsonBuilder.build(auth));
        email.setAuthResults(authEntity);

        EmailEntity saved = emailRepository.save(email);

        return new IngestResponse(saved.getId(), saved.getThreatScore(), saved.getVerdict(), saved.getStatus());
    }

    private void persistRuleHits(EmailEntity email, RuleEvaluationResult eval) {
        if (email == null || eval == null || eval.getHits() == null || eval.getHits().isEmpty()) return;

        for (var hit : eval.getHits()) {
            if (hit == null || hit.getRuleId() == null) continue;

            RuleEntity rule = ruleRepository.findById(hit.getRuleId()).orElse(null);
            if (rule == null) continue;

            RuleHitEntity e = new RuleHitEntity();
            e.setEmail(email);
            e.setRule(rule);
            e.setScoreDelta(hit.getScoreDelta());
            e.setForcedVerdict(hit.getForcedVerdict());
            e.setMessage(hit.getMessage());
            email.getRuleHits().add(e);
        }
    }

    private void applyAuthScoring(RuleEvaluationResult eval, EmailAuthEvaluation auth) {
        if (auth == null) return;

        if (auth.spfResult == SpfResult.FAIL) {
            eval.addScore(stableId("AUTH_SPF_FAIL"), "SPF fail", 15, auth.spfSummary != null ? auth.spfSummary : "SPF=fail");
        } else if (auth.spfResult == SpfResult.SOFTFAIL) {
            eval.addScore(stableId("AUTH_SPF_SOFTFAIL"), "SPF softfail", 8, auth.spfSummary != null ? auth.spfSummary : "SPF=softfail");
        }

        if (auth.dkimResult == DkimResult.FAIL) {
            eval.addScore(stableId("AUTH_DKIM_FAIL"), "DKIM fail", 15, auth.dkimSummary != null ? auth.dkimSummary : "DKIM=fail");
        }

        if (auth.dmarcResult == DmarcResult.FAIL) {
            int delta = 30;
            String name = "DMARC fail";
            String msg = auth.dmarcSummary != null ? auth.dmarcSummary : "DMARC=fail";

            if (auth.dmarcPolicy == DmarcPolicy.QUARANTINE) {
                eval.addScore(stableId("AUTH_DMARC_FAIL_QUAR"), name + " (policy=quarantine)", delta, msg);
            } else if (auth.dmarcPolicy == DmarcPolicy.REJECT) {
                eval.addScore(stableId("AUTH_DMARC_FAIL_REJECT"), name + " (policy=reject)", delta, msg);
                eval.forceVerdict(stableId("AUTH_DMARC_FORCE_QUAR"), "DMARC policy reject", EmailVerdict.QUARANTINE,
                        "DMARC failed and policy is reject; quarantining");
            } else {
                eval.addScore(stableId("AUTH_DMARC_FAIL"), name, delta, msg);
            }
        }
    }

    private UUID stableId(String name) {
        return UUID.nameUUIDFromBytes(("email-firewall:" + name).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private EmailVerdict determineVerdict(int score, EmailVerdict forced) {
        if (forced != null) return forced;
        if (score >= 70) return EmailVerdict.BLOCK;
        if (score >= 30) return EmailVerdict.QUARANTINE;
        return EmailVerdict.ALLOW;
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
            sb.append("]}");
            sb.append(',');

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
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
        }
    }
}
