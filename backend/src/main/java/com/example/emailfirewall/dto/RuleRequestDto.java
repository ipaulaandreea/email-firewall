package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.RuleAction;
import com.example.emailfirewall.enums.RuleTarget;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record RuleRequestDto(
        @NotBlank String name,
        @NotNull RuleTarget target,
        @NotNull RuleAction action,

        @NotBlank String pattern,
        Integer scoreDelta,
        EmailVerdict verdict,

        Integer priority,
        Boolean enabled
) {
    @AssertTrue(message = "Invalid rule: scoreDelta is required for ADD_SCORE; verdict is required for SET_VERDICT; BYPASS must not set scoreDelta/verdict.")
    public boolean isActionPayloadValid() {
        if (action == null) return true;

        return switch (action) {
            case ADD_SCORE -> scoreDelta != null;
            case SET_VERDICT -> verdict != null;
            case BYPASS -> scoreDelta == null && verdict == null;
        };
    }
}
