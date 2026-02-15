package com.example.emailfirewall.service;

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

    public RuleEvaluationResult evaluate(String fromAddress, String subject) {
        RuleEvaluationResult result = new RuleEvaluationResult();

        String from = fromAddress != null ? fromAddress.trim() : "";
        String domain = extractDomain(from);
        String subj = subject != null ? subject : "";

        List<RuleEntity> rules = ruleRepository.findByEnabledTrueOrderByPriorityAsc();

        for (RuleEntity rule : rules) {
            if (rule.getTarget() == null || rule.getAction() == null) continue;

            boolean matched = matches(rule, from, domain, subj);
            if (!matched) continue;

            apply(rule, result);

            // dacă o regulă setează verdict BLOCK/QUARANTINE, putem opri evaluarea (opțional)
            if (result.getForcedVerdict() == EmailVerdict.BLOCK) {
                break;
            }
        }

        return result;
    }

    private boolean matches(RuleEntity rule, String from, String domain, String subject) {
        String pattern = rule.getPattern();
        if (pattern == null || pattern.isBlank()) return false;

        RuleTarget target = rule.getTarget();

        return switch (target) {
            case SENDER_EMAIL -> equalsIgnoreCase(from, pattern);
            case SENDER_DOMAIN -> equalsIgnoreCase(domain, pattern) || domain.endsWith("." + pattern.toLowerCase(Locale.ROOT));
            case SUBJECT -> regexMatch(subject, pattern);
            default -> false; // MVP: doar astea 3
        };
    }

    private void apply(RuleEntity rule, RuleEvaluationResult result) {
        if (rule.getAction() == RuleAction.ADD_SCORE) {
            int delta = rule.getScoreDelta() != null ? rule.getScoreDelta() : 0;
            result.addScore(delta, rule.getName());
            return;
        }

        if (rule.getAction() == RuleAction.SET_VERDICT) {
            EmailVerdict verdict = rule.getVerdict(); // presupunem că e EmailVerdict în entity
            if (verdict != null) {
                result.forceVerdict(verdict, rule.getName());
            }
        }
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
            return Pattern.compile(regex).matcher(text).find();
        } catch (Exception ignored) {
            return false;
        }
    }
}
