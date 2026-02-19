package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.RuleAction;
import com.example.emailfirewall.enums.RuleTarget;

import java.util.UUID;

public record RuleResponseDto(
        UUID id,
        String name,
        RuleTarget target,
        RuleAction action,
        String pattern,
        Integer scoreDelta,
        EmailVerdict verdict,
        Integer priority,
        Boolean enabled
) {}
