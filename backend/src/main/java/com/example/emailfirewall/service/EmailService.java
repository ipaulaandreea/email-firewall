package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.EmailAuthEvaluation;
import com.example.emailfirewall.dto.IngestEmailRequest;
import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.entity.AuthResultsEntity;
import com.example.emailfirewall.entity.EmailEntity;
import com.example.emailfirewall.entity.RuleHitEntity;
import com.example.emailfirewall.enums.*;
import com.example.emailfirewall.repository.EmailRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final EmailRepository emailRepository;
    private final RuleEvaluationService ruleEvaluationService;
    private final EmailAuthService emailAuthService;

    public IngestResponse ingestJson(IngestEmailRequest req) {
        ParsedEmail p = new ParsedEmail();

        p.from = req.from();

        if (req.to() != null) {
            p.to.addAll(req.to());
        }

        p.subject = req.subject();
        p.bodyText = req.bodyText();
        p.bodyHtml = req.bodyHtml();

        if (req.headers() != null) {
            req.headers().forEach((k, v) -> p.headers.put(k, List.of(v)));
        }

        return ingestParsedEmail(p, IngestSource.JSON_API);
    }

    public IngestResponse ingestParsedEmail(ParsedEmail p, IngestSource source) {
        if (p == null) {
            p = new ParsedEmail();
        }

        EmailEntity email = new EmailEntity();

        email.setId(UUID.randomUUID());
        email.setIngestSource(source);
        email.setFromAddress(p.from != null ? p.from : "unknown");
        email.setSubject(p.subject);
        email.setBodyText(p.bodyText);
        email.setBodyHtmlSanitized(
                p.bodyHtml != null ? HtmlUtils.htmlEscape(p.bodyHtml) : null
        );

        ensureEmailCollections(email);

        if (p.to != null) {
            email.getToAddresses().addAll(p.to);
        }

        EmailAuthEvaluation auth = emailAuthService.evaluate(p);
        RuleEvaluationResult eval = ruleEvaluationService.evaluate(p);

        if (eval == null) {
            eval = new RuleEvaluationResult();
        }

        applyAuthScoring(eval, auth);

        int score = eval.getTotalScore();
        EmailVerdict verdict = determineVerdict(score, eval.getForcedVerdict());

        email.setThreatScore(score);
        email.setVerdict(verdict);
        email.setStatus(verdict == EmailVerdict.QUARANTINE
                ? EmailStatus.QUARANTINED
                : EmailStatus.ANALYZED);

        persistRuleHits(email, eval);
        persistAuthResults(email, auth);

        EmailEntity saved = emailRepository.save(email);

        return new IngestResponse(
                saved.getId(),
                saved.getThreatScore(),
                saved.getVerdict(),
                saved.getStatus()
        );
    }

    private void ensureEmailCollections(EmailEntity email) {
        if (email.getToAddresses() == null) {
            email.setToAddresses(new ArrayList<>());
        }

        if (email.getRuleHits() == null) {
            email.setRuleHits(new ArrayList<>());
        }

        if (email.getHeaders() == null) {
            email.setHeaders(new ArrayList<>());
        }

        if (email.getAttachments() == null) {
            email.setAttachments(new ArrayList<>());
        }

        if (email.getLinks() == null) {
            email.setLinks(new ArrayList<>());
        }
    }

    private void persistRuleHits(EmailEntity email, RuleEvaluationResult eval) {

        if (email == null || eval == null || eval.getHits() == null || eval.getHits().isEmpty()) {

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

    private void applyAuthScoring(RuleEvaluationResult eval, EmailAuthEvaluation auth) {
        if (eval == null || auth == null) return;

        if (auth.spfResult == SpfResult.FAIL) {
            eval.addScore(15, null, auth.spfSummary != null ? auth.spfSummary : "SPF=fail");
        } else if (auth.spfResult == SpfResult.SOFTFAIL) {
            eval.addScore(8, null, auth.spfSummary != null ? auth.spfSummary : "SPF=softfail");
        } else if (auth.spfResult == SpfResult.NONE) {
            eval.addScore(5, null, auth.spfSummary != null ? auth.spfSummary : "SPF missing");
        }

        if (auth.dkimResult == DkimResult.FAIL) {
            eval.addScore(15, null, auth.dkimSummary != null ? auth.dkimSummary : "DKIM=fail");
        } else if (auth.dkimResult == DkimResult.NONE) {
            eval.addScore(5, null, auth.dkimSummary != null ? auth.dkimSummary : "DKIM missing");
        }

        if (auth.dmarcResult == DmarcResult.FAIL) {
            int delta = switch (auth.dmarcPolicy) {
                case REJECT -> 40;
                case QUARANTINE -> 30;
                case NONE, UNKNOWN -> 20;
            };

            eval.addScore(delta, null, auth.dmarcSummary != null ? auth.dmarcSummary : "DMARC=fail");

            if (auth.dmarcPolicy == DmarcPolicy.REJECT) {
                eval.forceVerdict(
                        EmailVerdict.QUARANTINE,
                        null,
                        "DMARC failed and policy is reject; quarantining"
                );
            }
        } else if (auth.dmarcResult == DmarcResult.NONE) {
            eval.addScore(5, null, auth.dmarcSummary != null ? auth.dmarcSummary : "DMARC missing");
        }
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
            if (a.spfDomain != null) {
                sb.append(",\"domain\":\"").append(escape(a.spfDomain)).append("\"");
            }
            if (a.spfSummary != null) {
                sb.append(",\"summary\":\"").append(escape(a.spfSummary)).append("\"");
            }
            sb.append("},");

            sb.append("\"dkim\":{");
            sb.append("\"result\":\"").append(a.dkimResult).append("\"");
            if (a.dkimSummary != null) {
                sb.append(",\"summary\":\"").append(escape(a.dkimSummary)).append("\"");
            }

            sb.append(",\"signatures\":[");
            if (a.dkimSignatures != null) {
                for (int i = 0; i < a.dkimSignatures.size(); i++) {
                    var s = a.dkimSignatures.get(i);
                    if (i > 0) sb.append(',');

                    sb.append('{');

                    boolean hasPrevious = false;

                    if (s.domain != null) {
                        sb.append("\"domain\":\"").append(escape(s.domain)).append("\"");
                        hasPrevious = true;
                    }

                    if (s.selector != null) {
                        if (hasPrevious) sb.append(',');
                        sb.append("\"selector\":\"").append(escape(s.selector)).append("\"");
                        hasPrevious = true;
                    }

                    if (hasPrevious) sb.append(',');
                    sb.append("\"result\":\"").append(s.result).append("\"");

                    if (s.summary != null) {
                        sb.append(",\"summary\":\"").append(escape(s.summary)).append("\"");
                    }

                    sb.append('}');
                }
            }
            sb.append("]");
            sb.append("},");

            sb.append("\"dmarc\":{");
            sb.append("\"result\":\"").append(a.dmarcResult).append("\",");
            sb.append("\"policy\":\"").append(a.dmarcPolicy).append("\"");

            if (a.dmarcSpfAligned != null) {
                sb.append(",\"spfAligned\":").append(a.dmarcSpfAligned);
            }

            if (a.dmarcDkimAligned != null) {
                sb.append(",\"dkimAligned\":").append(a.dmarcDkimAligned);
            }

            if (a.dmarcSummary != null) {
                sb.append(",\"summary\":\"").append(escape(a.dmarcSummary)).append("\"");
            }

            sb.append('}');
            sb.append('}');

            return sb.toString();
        }

        private static String escape(String s) {
            if (s == null) return "";
            return s
                    .replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r");
        }
    }
}