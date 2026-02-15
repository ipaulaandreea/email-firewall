package com.example.emailfirewall.dto;

import java.util.List;
import java.util.Map;

public record IngestEmailRequest(
        String from,
        List<String> to,
        String subject,
        String bodyText,
        String bodyHtml,
        Map<String, String> headers
) {}
