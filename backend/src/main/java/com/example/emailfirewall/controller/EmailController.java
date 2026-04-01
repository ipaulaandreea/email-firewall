package com.example.emailfirewall.controller;

import com.example.emailfirewall.dto.EmailAuthDetailsResponse;
import com.example.emailfirewall.dto.EmailListItemResponse;
import com.example.emailfirewall.dto.RuleHitDto;
import com.example.emailfirewall.entity.EmailEntity;
import com.example.emailfirewall.repository.EmailRepository;
import com.example.emailfirewall.repository.RuleHitRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
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

    public EmailController(EmailRepository emailRepository, ObjectMapper objectMapper, RuleHitRepository ruleHitRepository) {
        this.emailRepository = emailRepository;
        this.objectMapper = objectMapper;
        this.ruleHitRepository = ruleHitRepository;
    }

    @GetMapping
    public ResponseEntity<List<EmailListItemResponse>> listRecent() {
        List<EmailEntity> emails = emailRepository.findTop50ByOrderByReceivedAtDesc();

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
                    auth != null ? auth.getDmarcPolicy() : null
            );
        }).toList();

        return ResponseEntity.ok(out);
    }

    @GetMapping("/{id}/auth")
    public ResponseEntity<EmailAuthDetailsResponse> getAuthDetails(@PathVariable("id") UUID id) {
        EmailEntity email = emailRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Email not found"));

        var auth = email.getAuthResults();

        Map<String, Object> details = null;
        if (auth != null && auth.getDetailsJson() != null && !auth.getDetailsJson().isBlank()) {
            try {
                details = objectMapper.readValue(auth.getDetailsJson(), new TypeReference<>() {});
            } catch (Exception ignored) {
                // If stored JSON is malformed, don't fail the request; just omit details.
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
        // ensure email exists
        if (!emailRepository.existsById(id)) {
            throw new IllegalArgumentException("Email not found");
        }

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
}
