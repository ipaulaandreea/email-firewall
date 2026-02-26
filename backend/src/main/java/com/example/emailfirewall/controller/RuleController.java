package com.example.emailfirewall.controller;

import com.example.emailfirewall.dto.RuleRequestDto;
import com.example.emailfirewall.dto.RuleResponseDto;
import com.example.emailfirewall.entity.RuleEntity;
import com.example.emailfirewall.repository.RuleRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/rules")
@RequiredArgsConstructor
public class RuleController {

    private final RuleRepository ruleRepository;

    @GetMapping
    public List<RuleResponseDto> list() {
        return ruleRepository.findAllByOrderByPriorityAsc()
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @GetMapping("/{id}")
    public RuleResponseDto get(@PathVariable UUID id) {
        RuleEntity r = ruleRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Rule not found: " + id));
        return toResponse(r);
    }

    @PostMapping
    public ResponseEntity<RuleResponseDto> create(@Valid @RequestBody RuleRequestDto req) {
        RuleEntity r = new RuleEntity();
        applyRequest(r, req);
        if (r.getEnabled() == null) r.setEnabled(true);
        if (r.getPriority() == null) r.setPriority(100);

        RuleEntity saved = ruleRepository.save(r);
        return ResponseEntity.ok(toResponse(saved));
    }

    @PutMapping("/{id}")
    public RuleResponseDto update(@PathVariable UUID id, @Valid @RequestBody RuleRequestDto req) {
        RuleEntity r = ruleRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Rule not found: " + id));
        applyRequest(r, req);
        return toResponse(ruleRepository.save(r));
    }

    @PatchMapping("/{id}/enabled")
    public RuleResponseDto setEnabled(@PathVariable UUID id, @RequestParam boolean value) {
        RuleEntity r = ruleRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Rule not found: " + id));
        r.setEnabled(value);
        return toResponse(ruleRepository.save(r));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        if (!ruleRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        ruleRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    private void applyRequest(RuleEntity r, RuleRequestDto req) {
        r.setName(req.name());
        r.setTarget(req.target());
        r.setAction(req.action());

        r.setPattern(req.pattern());
        r.setScoreDelta(req.scoreDelta());
        r.setVerdict(req.verdict());

        if (req.priority() != null) r.setPriority(req.priority());
        if (req.enabled() != null) r.setEnabled(req.enabled());
    }

    private RuleResponseDto toResponse(RuleEntity r) {
        return new RuleResponseDto(
                r.getId(),
                r.getName(),
                r.getTarget(),
                r.getAction(),
                r.getPattern(),
                r.getScoreDelta(),
                r.getVerdict(),
                r.getPriority(),
                r.getEnabled()
        );
    }
}
