package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.*;

import java.time.Instant;
import java.util.UUID;

public record EmailListItemResponse(
        UUID emailId,
        Instant receivedAt,
        String fromAddress,
        String subject,
        Integer threatScore,
        EmailVerdict verdict,
        EmailStatus status,
        SpfResult spfResult,
        DkimResult dkimResult,
        DmarcResult dmarcResult,
        String urlStatus,
        Integer suspiciousUrlCount,
        String attachmentStatus,
        Integer attachmentCount,
        Integer suspiciousAttachmentCount,
        Integer aiSpamScore,
        String aiClassification
) {}

