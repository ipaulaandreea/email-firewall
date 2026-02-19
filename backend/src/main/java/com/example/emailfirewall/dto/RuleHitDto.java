package com.example.emailfirewall.dto;
import com.example.emailfirewall.enums.EmailVerdict;
import lombok.Getter;

import java.time.Instant;
import java.util.UUID;

@Getter
public class RuleHitDto {

    private final UUID ruleId;
    private final String ruleName;

    private final Integer scoreDelta;
    private final EmailVerdict forcedVerdict;

    private final String message;
    private final Instant timestamp;

    public RuleHitDto(UUID ruleId,
                      String ruleName,
                      Integer scoreDelta,
                      EmailVerdict forcedVerdict,
                      String message,
                      Instant timestamp) {
        this.ruleId = ruleId;
        this.ruleName = ruleName;
        this.scoreDelta = scoreDelta;
        this.forcedVerdict = forcedVerdict;
        this.message = message;
        this.timestamp = timestamp;
    }
}

