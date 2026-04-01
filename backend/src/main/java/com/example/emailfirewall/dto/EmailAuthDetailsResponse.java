package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.*;

import java.util.Map;
import java.util.UUID;

public record EmailAuthDetailsResponse(
        UUID emailId,
        Integer threatScore,
        EmailVerdict verdict,
        EmailStatus status,
        SpfResult spfResult,
        DkimResult dkimResult,
        DmarcResult dmarcResult,
        DmarcPolicy dmarcPolicy,
        Map<String, Object> details
) {}

