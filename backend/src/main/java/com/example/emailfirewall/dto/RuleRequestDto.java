package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.RuleAction;
import com.example.emailfirewall.enums.RuleTarget;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RuleRequestDto(
        @NotBlank String name,
        @NotNull RuleTarget target,
        @NotNull RuleAction action,

        String pattern,
        Integer scoreDelta,
        EmailVerdict verdict,

        Integer priority,
        Boolean enabled
) {}
