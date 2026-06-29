package com.example.emailfirewall.controller;

import com.example.emailfirewall.dto.MailboxFetchRequest;
import com.example.emailfirewall.service.MailboxFetchService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/mailbox")
@RequiredArgsConstructor
public class MailboxController {

    private final MailboxFetchService mailboxFetchService;


    @PostMapping("/analyze")
    public Map<String, String> analyze(@RequestBody MailboxFetchRequest req) throws Exception {
        mailboxFetchService.analyzeInbox(
                req.host(),
                req.username(),
                req.password(),
                req.limit()
        );

        return Map.of("status", "ANALYZED");
    }

    @PostMapping("/fetch")
    public Map<String, String> fetchAndMove(@RequestBody MailboxFetchRequest req) throws Exception {
        int moved = mailboxFetchService.fetchAndMoveInbox(
                req.host(),
                req.username(),
                req.password(),
                req.limit()
        );

        return Map.of(
                "status", "FETCHED_AND_MOVED",
                "moved", String.valueOf(moved)
        );
    }
}