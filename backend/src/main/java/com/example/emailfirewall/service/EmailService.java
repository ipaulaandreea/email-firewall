package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.IngestEmailRequest;
import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.entity.EmailEntity;
import com.example.emailfirewall.enums.EmailStatus;
import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.IngestSource;
import com.example.emailfirewall.repository.EmailRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final EmailRepository emailRepository;
    private final RuleEvaluationService ruleEvaluationService;

    public IngestResponse ingestJson(IngestEmailRequest req) {
        ParsedEmail p = new ParsedEmail();
        p.from = req.from();
        if (req.to() != null) p.to.addAll(req.to());
        p.subject = req.subject();
        p.bodyText = req.bodyText();
        p.bodyHtml = req.bodyHtml();
        if (req.headers() != null) p.headers.putAll(req.headers());

        return ingestParsedEmail(p, IngestSource.JSON_API);
    }

    public IngestResponse ingestParsedEmail(ParsedEmail p, IngestSource source) {
        EmailEntity email = new EmailEntity();
        email.setId(UUID.randomUUID());
        email.setIngestSource(source);

        email.setFromAddress(p.from != null ? p.from : "unknown");
        email.setSubject(p.subject);
        email.setBodyText(p.bodyText);
        email.setBodyHtmlSanitized(p.bodyHtml);

        if (p.to != null) email.getToAddresses().addAll(p.to);

        email.setStatus(EmailStatus.RECEIVED);
        email.setVerdict(EmailVerdict.ALLOW);
        email.setThreatScore(0);

        emailRepository.save(email);

        RuleEvaluationResult eval = ruleEvaluationService.evaluate(email.getFromAddress(), email.getSubject());

        int score = eval.getTotalScore();
        EmailVerdict verdict = determineVerdict(score, eval.getForcedVerdict());

        email.setThreatScore(score);
        email.setVerdict(verdict);
        email.setStatus(verdict == EmailVerdict.QUARANTINE ? EmailStatus.QUARANTINED : EmailStatus.ANALYZED);

        EmailEntity saved = emailRepository.save(email);

        return new IngestResponse(saved.getId(), saved.getThreatScore(), saved.getVerdict(), saved.getStatus());
    }

    private EmailVerdict determineVerdict(int score, EmailVerdict forced) {
        if (forced != null) return forced;
        if (score >= 70) return EmailVerdict.BLOCK;
        if (score >= 30) return EmailVerdict.QUARANTINE;
        return EmailVerdict.ALLOW;
    }
}
