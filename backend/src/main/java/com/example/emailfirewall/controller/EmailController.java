package com.example.emailfirewall.controller;

import com.example.emailfirewall.dto.EmailAuthDetailsResponse;
import com.example.emailfirewall.dto.EmailListItemResponse;
import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.dto.RuleHitDto;
import com.example.emailfirewall.entity.EmailEntity;
import com.example.emailfirewall.repository.EmailRepository;
import com.example.emailfirewall.repository.RuleHitRepository;
import com.example.emailfirewall.service.EmailService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/emails")
public class EmailController {

    private final EmailRepository emailRepository;
    private final ObjectMapper objectMapper;
    private final RuleHitRepository ruleHitRepository;
    private final EmailService emailService;

    public EmailController(EmailRepository emailRepository, ObjectMapper objectMapper, RuleHitRepository ruleHitRepository, EmailService emailService) {
        this.emailRepository = emailRepository;
        this.objectMapper = objectMapper;
        this.ruleHitRepository = ruleHitRepository;
        this.emailService = emailService;
    }

    private String urlStatus(EmailEntity e) {
        if (e.getLinks() == null || e.getLinks().isEmpty()) {
            return "NONE";
        }

        boolean suspicious = e.getLinks().stream()
                .anyMatch(l ->
                        "SUSPICIOUS".equalsIgnoreCase(l.getVerdict())
                                || "WARNING".equalsIgnoreCase(l.getVerdict())
                );

        return suspicious ? "SUSPICIOUS" : "CLEAN";
    }

    private int suspiciousUrlCount(EmailEntity e) {
        if (e.getLinks() == null) return 0;

        return (int) e.getLinks().stream()
                .filter(l ->
                        "SUSPICIOUS".equalsIgnoreCase(l.getVerdict())
                                || "WARNING".equalsIgnoreCase(l.getVerdict())
                )
                .count();
    }

    private String attachmentStatus(EmailEntity e) {
        if (e.getAttachments() == null || e.getAttachments().isEmpty()) {
            return "NONE";
        }

        boolean suspicious = e.getAttachments().stream()
                .anyMatch(a ->
                        "SUSPICIOUS".equalsIgnoreCase(a.getVerdict())
                                || "WARNING".equalsIgnoreCase(a.getVerdict())
                );

        return suspicious ? "SUSPICIOUS" : "CLEAN";
    }

    private int attachmentCount(EmailEntity e) {
        if (e.getAttachments() == null) return 0;
        return e.getAttachments().size();
    }

    private int suspiciousAttachmentCount(EmailEntity e) {
        if (e.getAttachments() == null) return 0;

        return (int) e.getAttachments().stream()
                .filter(a ->
                        "SUSPICIOUS".equalsIgnoreCase(a.getVerdict())
                                || "WARNING".equalsIgnoreCase(a.getVerdict())
                )
                .count();
    }


    @GetMapping
    public ResponseEntity<List<EmailListItemResponse>> listRecent() {
        List<EmailEntity> emails = isAdmin()
                ? emailRepository.findTop50ByOrderByReceivedAtDesc()
                : emailRepository.findTop50ByOwnerUsernameOrderByReceivedAtDesc(currentUsername());

        List<EmailListItemResponse> out = emails.stream().map(e -> {
            var auth = e.getAuthResults();
            return new EmailListItemResponse(
                    e.getId(),
                    e.getReceivedAt(),
                    e.getFromAddress(),
                    e.getSubject(),
                    e.getThreatScore(),
                    e.getVerdict(),
                    e.getStatus(),
                    auth != null ? auth.getSpfResult() : null,
                    auth != null ? auth.getDkimResult() : null,
                    auth != null ? auth.getDmarcResult() : null,
                    urlStatus(e),
                    suspiciousUrlCount(e),
                    attachmentStatus(e),
                    attachmentCount(e),
                    suspiciousAttachmentCount(e),
                    e.getAiSpamScore(),
                    e.getAiClassification()
            );
        }).toList();

        return ResponseEntity.ok(out);
    }

    private Authentication auth() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private String currentUsername() {
        Authentication a = auth();
        return a != null ? a.getName() : "anonymous";
    }

    private boolean isAdmin() {
        Authentication a = auth();
        return a != null && a.getAuthorities().stream()
                .anyMatch(x -> "ROLE_ADMIN".equals(x.getAuthority()));
    }

    private EmailEntity getVisibleEmail(UUID id) {
        EmailEntity email = emailRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Email not found"));

        if (!isAdmin() && !currentUsername().equals(email.getOwnerUsername())) {
            throw new IllegalArgumentException("Email not found");
        }

        return email;
    }

    @GetMapping("/{id}/auth")
    public ResponseEntity<EmailAuthDetailsResponse> getAuthDetails(@PathVariable("id") UUID id) {
        EmailEntity email = getVisibleEmail(id);

        var auth = email.getAuthResults();

        Map<String, Object> details = null;
        if (auth != null && auth.getDetailsJson() != null && !auth.getDetailsJson().isBlank()) {
            try {
                details = objectMapper.readValue(auth.getDetailsJson(), new TypeReference<>() {});
            } catch (Exception ignored) {
                details = null;
            }
        }

        EmailAuthDetailsResponse resp = new EmailAuthDetailsResponse(
                email.getId(),
                email.getThreatScore(),
                email.getVerdict(),
                email.getStatus(),
                auth != null ? auth.getSpfResult() : null,
                auth != null ? auth.getDkimResult() : null,
                auth != null ? auth.getDmarcResult() : null,
                auth != null ? auth.getDmarcPolicy() : null,
                details
        );

        return ResponseEntity.ok(resp);
    }


    @GetMapping("/{id}/rule-hits")
    public ResponseEntity<List<RuleHitDto>> getRuleHits(@PathVariable("id") UUID id) {
        getVisibleEmail(id);

        var hits = ruleHitRepository.findByEmail_IdOrderByHitAtAsc(id);

        List<RuleHitDto> out = hits.stream().map(h -> new RuleHitDto(
                h.getRule() != null ? h.getRule().getId() : null,
                h.getRule() != null ? h.getRule().getName() : null,
                h.getScoreDelta(),
                h.getForcedVerdict(),
                h.getMessage(),
                h.getHitAt()
        )).toList();

        return ResponseEntity.ok(out);
    }

    @GetMapping("/{id}/security")
    public ResponseEntity<Map<String, Object>> getSecurityDetails(@PathVariable UUID id) {
        EmailEntity email = getVisibleEmail(id);

        List<Map<String, Object>> urls = email.getLinks() == null
                ? List.of()
                : email.getLinks().stream().map(l -> Map.<String, Object>of(
                "url", l.getUrlRaw(),
                "host", l.getHost(),
                "verdict", l.getVerdict(),
                "shortener", Boolean.TRUE.equals(l.getShortener())
        )).toList();

        List<Map<String, Object>> attachments = email.getAttachments() == null
                ? List.of()
                : email.getAttachments().stream().map(a -> Map.<String, Object>of(
                "filename", a.getFilename(),
                "contentType", a.getContentType(),
                "sizeBytes", a.getSizeBytes(),
                "sha256", a.getSha256(),
                "extension", a.getExtension(),
                "verdict", a.getVerdict()
        )).toList();

        return ResponseEntity.ok(Map.of(
                "emailId", email.getId(),
                "urlStatus", urlStatus(email),
                "suspiciousUrlCount", suspiciousUrlCount(email),
                "urls", urls,
                "attachmentStatus", attachmentStatus(email),
                "attachmentCount", attachmentCount(email),
                "suspiciousAttachmentCount", suspiciousAttachmentCount(email),
                "attachments", attachments
        ));
    }

    @PostMapping("/{id}/analyze-spam")
    public IngestResponse analyzeSpam(@PathVariable UUID id) {
        getVisibleEmail(id);
        return emailService.analyzeSpam(id);
    }
}
