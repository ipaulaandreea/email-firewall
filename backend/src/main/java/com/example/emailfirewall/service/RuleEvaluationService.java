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

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class RuleEvaluationService {

    private final RuleRepository ruleRepository;

    public RuleEvaluationResult evaluate(ParsedEmail email) {
        RuleEvaluationResult result = new RuleEvaluationResult();

        String from = email != null && email.from != null ? email.from.trim() : "";
        String domain = extractDomain(from);
        String subject = email != null && email.subject != null ? email.subject : "";
        String body = ((email != null && email.bodyText != null) ? email.bodyText : "")
                + "\n"
                + ((email != null && email.bodyHtml != null) ? email.bodyHtml : "");

        List<RuleEntity> rules = ruleRepository.findByEnabledTrueOrderByPriorityAsc();

        for (RuleEntity rule : rules) {
            if (rule.getTarget() == null || rule.getAction() == null) continue;

            boolean matched = matches(rule, email, from, domain, subject, body);
            if (!matched) continue;

            apply(rule, result);

            if (result.isBypassTriggered()) {
                break;
            }

            if (result.getForcedVerdict() == EmailVerdict.BLOCK) {
                break;
            }
        }

        return result;
    }

    public RuleEvaluationResult evaluate(String fromAddress, String subject) {
        ParsedEmail email = new ParsedEmail();
        email.from = fromAddress;
        email.subject = subject;
        return evaluate(email);
    }

    private boolean matches(
            RuleEntity rule,
            ParsedEmail email,
            String from,
            String domain,
            String subject,
            String body
    ) {
        String pattern = rule.getPattern();
        if (pattern == null || pattern.isBlank()) return false;

        RuleTarget target = rule.getTarget();

        return switch (target) {
            case SENDER_EMAIL -> equalsIgnoreCase(from, pattern);
            case SENDER_DOMAIN -> equalsIgnoreCase(domain, pattern)
                    || domain.endsWith("." + pattern.toLowerCase(Locale.ROOT));
            case SUBJECT -> regexMatch(subject, pattern);
            case BODY -> regexMatch(body, pattern);
            case ATTACHMENT_EXT -> attachmentExtMatch(email, pattern);
            case ATTACHMENT_SIZE -> attachmentSizeMatch(email, pattern);
        };
    }

    private void apply(RuleEntity rule, RuleEvaluationResult result) {
        if (rule.getAction() == RuleAction.BYPASS) {
            result.triggerBypass(rule, "Bypass de la regula: " + rule.getName());
        }
        if (rule.getAction() == RuleAction.ADD_SCORE) {
            int delta = rule.getScoreDelta() != null ? rule.getScoreDelta() : 0;
            result.addScore(delta, rule, "Regulă declanșată: " + rule.getName());
            return;
        }

        if (rule.getAction() == RuleAction.SET_VERDICT && rule.getVerdict() != null) {
            result.forceVerdict(rule.getVerdict(), rule, "Verdict forțat de regula: " + rule.getName());
            return;
        }
    }

    private boolean attachmentExtMatch(ParsedEmail email, String pattern) {
        if (email == null || email.attachments == null) return false;

        String wanted = pattern.toLowerCase(Locale.ROOT).replace(".", "").trim();

        for (AttachmentMeta a : email.attachments) {
            String filename = a.filename != null ? a.filename.toLowerCase(Locale.ROOT) : "";
            if (filename.endsWith("." + wanted)) return true;
        }

        return false;
    }

    private boolean attachmentSizeMatch(ParsedEmail email, String pattern) {
        if (email == null || email.attachments == null) return false;

        long limit;
        try {
            limit = Long.parseLong(pattern.trim());
        } catch (Exception e) {
            return false;
        }

        for (AttachmentMeta a : email.attachments) {
            if (a.size >= limit) return true;
        }

        return false;
    }

    private String extractDomain(String email) {
        int at = email.lastIndexOf('@');
        if (at < 0 || at == email.length() - 1) return "";
        return email.substring(at + 1).toLowerCase(Locale.ROOT);
    }

    private boolean equalsIgnoreCase(String a, String b) {
        return a != null && b != null && a.equalsIgnoreCase(b.trim());
    }

    private boolean regexMatch(String text, String regex) {
        try {
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(text).find();
        } catch (Exception ignored) {
            return false;
        }
    }
}