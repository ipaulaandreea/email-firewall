package com.example.emailfirewall.dto;

public record IngestErrorResponse(
        String message,
        String errorCode,
        int statusCode
) {}
