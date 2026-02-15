package com.example.emailfirewall.controller;

import com.example.emailfirewall.dto.BatchIngestItemResponse;
import com.example.emailfirewall.dto.IngestEmailRequest;
import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.enums.IngestSource;
import com.example.emailfirewall.service.AsyncIngestService;
import com.example.emailfirewall.service.EmailService;
import com.example.emailfirewall.service.EmlParserService;
import com.example.emailfirewall.service.ParsedEmail;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/api/ingest")
@RequiredArgsConstructor
public class IngestController {

    private final EmailService emailService;
    private final EmlParserService emlParserService;
    private final AsyncIngestService asyncIngestService;

    @PostMapping("/json")
    public ResponseEntity<IngestResponse> ingestJson(@RequestBody IngestEmailRequest request) {
        return ResponseEntity.ok(emailService.ingestJson(request));
    }

    @PostMapping(value = "/eml", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<IngestResponse> ingestEml(@RequestPart("file") MultipartFile file) throws Exception {
        ParsedEmail parsed = emlParserService.parse(file.getInputStream());
        return ResponseEntity.ok(emailService.ingestParsedEmail(parsed, IngestSource.EML_API));
    }

    @PostMapping(value = "/eml/batch", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<List<BatchIngestItemResponse>> ingestEmlBatch(
            @RequestPart("files") MultipartFile[] files
    ) {
        List<CompletableFuture<BatchIngestItemResponse>> futures = new ArrayList<>();

        for (MultipartFile f : files) {
            CompletableFuture<BatchIngestItemResponse> fut =
                    asyncIngestService.ingestOneEmlAsync(f)
                            .thenApply(res -> new BatchIngestItemResponse(
                                    safeName(f), true, res, null
                            ))
                            .exceptionally(ex -> new BatchIngestItemResponse(
                                    safeName(f), false, null, rootMessage(ex)
                            ));

            futures.add(fut);
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        List<BatchIngestItemResponse> out = futures.stream().map(CompletableFuture::join).toList();
        return ResponseEntity.ok(out);
    }

    private String safeName(MultipartFile f) {
        return (f != null && f.getOriginalFilename() != null) ? f.getOriginalFilename() : "unknown.eml";
    }

    private String rootMessage(Throwable ex) {
        Throwable t = ex;
        while (t.getCause() != null) t = t.getCause();
        return (t.getMessage() != null) ? t.getMessage() : t.toString();
    }
}
