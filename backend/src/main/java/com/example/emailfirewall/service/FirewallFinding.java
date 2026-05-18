package com.example.emailfirewall.service;

public record FirewallFinding(
        String source,
        String code,
        int scoreDelta,
        String message
) {}