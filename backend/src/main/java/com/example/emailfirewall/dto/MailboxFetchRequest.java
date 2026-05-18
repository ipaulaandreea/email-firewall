package com.example.emailfirewall.dto;

public record MailboxFetchRequest(
        String host,
        String username,
        String password,
        Integer limit
) {
}