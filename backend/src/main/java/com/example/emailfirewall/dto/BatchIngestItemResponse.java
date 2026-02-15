package com.example.emailfirewall.dto;

public record BatchIngestItemResponse(
        String filename,
        boolean success,
        IngestResponse result,
        String error
) {}
