package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.AuditAction;
import com.example.emailfirewall.enums.AuditEntityType;

import java.time.Instant;

public record AuditEventDto(
        Long id,
        Instant eventAt,
        String actorEmail,
        AuditEntityType entityType,
        String entityId,
        AuditAction action,
        String detailsJson
) {}
