package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.enums.IngestSource;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.concurrent.CompletableFuture;

@Service
@RequiredArgsConstructor
public class AsyncIngestService {

    private final EmlParserService emlParserService;
    private final EmailService emailService;

    @Async("ingestExecutor")
    @Transactional
    public CompletableFuture<IngestResponse> ingestOneEmlAsync(MultipartFile file) {
        try {
            ParsedEmail parsed = emlParserService.parse(file.getInputStream());
            IngestResponse resp = emailService.ingestParsedEmail(parsed, IngestSource.EML_API);
            return CompletableFuture.completedFuture(resp);
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }
}
