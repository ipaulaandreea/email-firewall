package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AttachmentMeta;
import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.entity.RuleEntity;
import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.RuleAction;
import com.example.emailfirewall.enums.RuleTarget;
import com.example.emailfirewall.repository.RuleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class RuleEvaluationService {

    private final RuleRepository ruleRepository;

    public RuleEvaluationResult evaluate(ParsedEmail email) {
        RuleEvaluationResult result = new RuleEvaluationResult();

        String from = norm(email != null ? email.from : null);
        String domain = extractDomain(from);

        String subject = email != null ? safe(email.subject) : "";
        String body = buildBody(email);

        List<RuleEntity> rules = ruleRepository.findByEnabledTrueOrderByPriorityAsc();

        for (RuleEntity r : rules) {
            if (!isEnabled(r)) continue;
            if (!isWhitelistRule(r)) continue;

            if (matches(r, from, domain, subject, body, email)) {
                apply(r, result, subject, body, email);

                if (result.getForcedVerdict() == null) {
                    result.forceVerdict(r.getId(), r.getName(), EmailVerdict.ALLOW,
                            "Whitelisted by rule: " + r.getName());
                }
                return result;
            }
        }

        for (RuleEntity r : rules) {
            if (!isEnabled(r)) continue;
            if (!isBlacklistRule(r)) continue;

            if (matches(r, from, domain, subject, body, email)) {
                apply(r, result, subject, body, email);

                if (result.getForcedVerdict() == null) {
                    result.forceVerdict(r.getId(), r.getName(), EmailVerdict.BLOCK,
                            "Blacklisted by rule: " + r.getName());
                }
                return result;
            }
        }

        for (RuleEntity r : rules) {
            if (!isEnabled(r)) continue;
            if (isWhitelistRule(r) || isBlacklistRule(r)) continue;

            if (!matches(r, from, domain, subject, body, email)) continue;

            apply(r, result, subject, body, email);

            if (result.getForcedVerdict() == EmailVerdict.BLOCK) break;
        }

        return result;
    }

    private boolean isEnabled(RuleEntity r) {
        return r != null
                && Boolean.TRUE.equals(r.getEnabled())
                && r.getTarget() != null
                && r.getAction() != null;
    }

    private boolean isWhitelistRule(RuleEntity r) {
        if (r.getAction() == RuleAction.BYPASS) return true;
        return r.getAction() == RuleAction.SET_VERDICT && r.getVerdict() == EmailVerdict.ALLOW;
    }

    private boolean isBlacklistRule(RuleEntity r) {
        return r.getAction() == RuleAction.SET_VERDICT && r.getVerdict() == EmailVerdict.BLOCK;
    }

    private boolean matches(RuleEntity rule,
                            String from,
                            String domain,
                            String subject,
                            String body,
                            ParsedEmail email) {

        RuleTarget target = rule.getTarget();
        String pattern = safe(rule.getPattern());
        if (pattern.isBlank()) return false;

        return switch (target) {
            case SENDER_EMAIL -> equalsIgnoreCase(from, pattern);
            case SENDER_DOMAIN -> domainMatch(domain, pattern);

            case SUBJECT -> textMatch(subject, rule, pattern);
            case BODY -> textMatch(body, rule, pattern);

            case ATTACHMENT_EXT -> attachmentExtensionMatch(email, pattern);
            case ATTACHMENT_SIZE -> attachmentSizeMatch(email, rule);

            default -> false;
        };
    }

    private void apply(RuleEntity rule, RuleEvaluationResult result, String subject, String body, ParsedEmail email) {

        if (rule.getAction() == RuleAction.ADD_SCORE) {
            int delta = rule.getScoreDelta() != null ? rule.getScoreDelta() : 0;
            result.addScore(rule.getId(), rule.getName(), delta, explain(rule, subject, body, email));
            return;
        }

        if (rule.getAction() == RuleAction.SET_VERDICT) {
            EmailVerdict verdict = rule.getVerdict();
            if (verdict != null) {
                result.forceVerdict(rule.getId(), rule.getName(), verdict, explain(rule, subject, body, email));
            }
            return;
        }

        if (rule.getAction() == RuleAction.BYPASS) {
            result.forceVerdict(rule.getId(), rule.getName(), EmailVerdict.ALLOW, explain(rule, subject, body, email));
        }
    }

    private boolean textMatch(String text, RuleEntity rule, String pattern) {
        String t = safe(text);

        if (pattern.regionMatches(true, 0, "kw:", 0, 3)) {
            String kw = pattern.substring(3).trim();
            return !kw.isBlank() && t.toLowerCase(Locale.ROOT).contains(kw.toLowerCase(Locale.ROOT));
        }

        return regexMatch(t, pattern);
    }

    private boolean attachmentExtensionMatch(ParsedEmail email, String pattern) {
        Set<String> blocked = parseExtensions(pattern);
        if (blocked.isEmpty() || email == null || email.attachments == null) return false;

        for (AttachmentMeta a : email.attachments) {
            String ext = fileExtension(a != null ? a.filename : null);
            if (!ext.isBlank() && blocked.contains(ext)) return true;
        }
        return false;
    }

    private boolean attachmentSizeMatch(ParsedEmail email, RuleEntity rule) {
        Long max = null;

        try {
            String p = safe(rule.getPattern());
            if (p.toLowerCase(Locale.ROOT).startsWith("max:")) {
                max = Long.parseLong(p.substring(4).trim());
            }
        } catch (Exception ignored) {}

        if (max == null || max <= 0 || email == null || email.attachments == null) return false;

        for (AttachmentMeta a : email.attachments) {
            if (a != null && a.size > max) return true;
        }
        return false;
    }

    private String explain(RuleEntity rule, String subject, String body, ParsedEmail email) {
        RuleTarget t = rule.getTarget();
        String pat = safe(rule.getPattern());

        return switch (t) {
            case SENDER_EMAIL -> "Sender email matched: " + pat;
            case SENDER_DOMAIN -> "Sender domain matched: " + pat;

            case SUBJECT -> "Subject matched (" + rule.getName() + ") pattern=" + pat;
            case BODY -> "Body matched (" + rule.getName() + ") pattern=" + pat;

            case ATTACHMENT_EXT -> {
                String hit = firstMatchingAttachmentExt(email, pat);
                yield hit != null ? "Blocked extension matched: " + hit
                        : "Attachment extension rule matched pattern=" + pat;
            }

            case ATTACHMENT_SIZE -> "Attachment size exceeded max (" + pat + ")";

            default -> "Rule matched: " + rule.getName();
        };
    }

    private String firstMatchingAttachmentExt(ParsedEmail email, String pattern) {
        Set<String> blocked = parseExtensions(pattern);
        if (blocked.isEmpty() || email == null || email.attachments == null) return null;

        for (AttachmentMeta a : email.attachments) {
            String ext = fileExtension(a != null ? a.filename : null);
            if (!ext.isBlank() && blocked.contains(ext)) {
                return ext + (a.filename != null ? " (" + a.filename + ")" : "");
            }
        }
        return null;
    }

    private String buildBody(ParsedEmail email) {
        if (email == null) return "";
        String t = safe(email.bodyText);
        String h = safe(email.bodyHtml);
        return (t + "\n" + h).trim();
    }

    private String safe(String s) { return s == null ? "" : s; }
    private String norm(String s) { return safe(s).trim(); }

    private String extractDomain(String email) {
        int at = email.lastIndexOf('@');
        if (at < 0 || at == email.length() - 1) return "";
        return email.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    }

    private boolean equalsIgnoreCase(String a, String b) {
        return a != null && b != null && a.trim().equalsIgnoreCase(b.trim());
    }

    private boolean domainMatch(String domain, String pattern) {
        String d = safe(domain).toLowerCase(Locale.ROOT);
        String p = safe(pattern).trim().toLowerCase(Locale.ROOT);
        if (p.isBlank()) return false;
        return d.equals(p) || d.endsWith("." + p);
    }

    private boolean regexMatch(String text, String regex) {
        try {
            return Pattern
                    .compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
                    .matcher(text != null ? text : "")
                    .find();
        } catch (Exception ignored) {
            return false;
        }
    }

    private Set<String> parseExtensions(String csv) {
        if (csv == null) return Set.of();
        String[] parts = csv.split("[,;\\s]+");
        Set<String> out = new HashSet<>();
        for (String p : parts) {
            String x = p.trim().toLowerCase(Locale.ROOT);
            if (x.startsWith(".")) x = x.substring(1);
            if (!x.isBlank()) out.add(x);
        }
        return out;
    }

    private String fileExtension(String filename) {
        if (filename == null) return "";
        String f = filename.trim();
        int dot = f.lastIndexOf('.');
        if (dot < 0 || dot == f.length() - 1) return "";
        return f.substring(dot + 1).toLowerCase(Locale.ROOT);
    }
}
