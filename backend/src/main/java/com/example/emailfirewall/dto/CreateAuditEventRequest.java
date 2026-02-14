package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.AuditAction;
import com.example.emailfirewall.enums.AuditEntityType;

public record CreateAuditEventRequest(
        AuditEntityType entityType,
        String entityId,
        AuditAction action,
        String detailsJson
) {

}
