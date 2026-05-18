package com.example.emailfirewall.dto;

import java.util.List;

public record AiSpamResult(
        Integer spamScore,
        String classification,
        String confidence,
        List<String> reasons,
        String explanation
) {}
