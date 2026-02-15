package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.EmailStatus;
import com.example.emailfirewall.enums.EmailVerdict;

import java.util.UUID;

public record IngestResponse(
        UUID emailId,
        Integer threatScore,
        EmailVerdict verdict,
        EmailStatus status
) {

}
