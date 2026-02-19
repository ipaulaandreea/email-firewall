package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.RuleHitDto;
import com.example.emailfirewall.enums.EmailVerdict;
import lombok.Getter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Getter
public class RuleEvaluationResult {

    private int totalScore;
    private EmailVerdict forcedVerdict;
    private final List<RuleHitDto> hits = new ArrayList<>();

    public void addScore(UUID ruleId, String ruleName, int delta, String message) {
        this.totalScore += delta;

        hits.add(new RuleHitDto(
                ruleId,
                ruleName,
                delta,
                null,
                message,
                Instant.now()));
    }

    public void forceVerdict(UUID ruleId, String ruleName, EmailVerdict verdict, String message) {
        this.forcedVerdict = verdict;
        hits.add(new RuleHitDto(
                ruleId,
                ruleName,
                null,
                verdict,
                message,
                Instant.now()
        ));
    }
}
