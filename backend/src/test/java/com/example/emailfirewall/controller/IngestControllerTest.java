package com.example.emailfirewall.controller;

import com.example.emailfirewall.dto.BatchIngestItemResponse;
import com.example.emailfirewall.dto.IngestEmailRequest;
import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.enums.EmailStatus;
import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.IngestSource;
import com.example.emailfirewall.service.AsyncIngestService;
import com.example.emailfirewall.service.EmailService;
import com.example.emailfirewall.service.EmlParserService;
import com.example.emailfirewall.service.ParsedEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IngestControllerTest {

    @Mock
    private EmailService emailService;

    @Mock
    private EmlParserService emlParserService;

    @Mock
    private AsyncIngestService asyncIngestService;

    @InjectMocks
    private IngestController ingestController;

    private IngestEmailRequest ingestRequest;
    private IngestResponse ingestResponse;
    private ParsedEmail parsedEmail;

    @BeforeEach
    void setUp() {
        ingestRequest = new IngestEmailRequest(
                "sender@example.com",
                List.of("recipient@example.com"),
                "Test Subject",
                "Test Body",
                "<html>Test Body</html>",
                Map.of("X-Custom-Header", "value")
        );

        ingestResponse = new IngestResponse(
                UUID.randomUUID(),
                1,
                EmailVerdict.ALLOW,
                EmailStatus.RECEIVED
        );

        parsedEmail = new ParsedEmail(
                "sender@example.com",
                List.of("recipient@example.com"),
                "Test Subject",
                "Test Body",
                "<html>Test Body</html>",
                Map.of(),
                List.of()
        );
    }

    @Test
    void ingestJson_ShouldReturnIngestResponse() {
        when(emailService.ingestJson(ingestRequest)).thenReturn(ingestResponse);

        ResponseEntity<IngestResponse> response = ingestController.ingestJson(ingestRequest);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().emailId());
        verify(emailService, times(1)).ingestJson(ingestRequest);
    }


    @Test
    void ingestEml_ShouldParseAndIngestEmail() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "test.eml",
                "message/rfc822",
                "email content".getBytes()
        );

        when(emlParserService.parse(any(InputStream.class))).thenReturn(parsedEmail);
        when(emailService.ingestParsedEmail(parsedEmail, IngestSource.EML_API)).thenReturn(ingestResponse);

        ResponseEntity<IngestResponse> response = ingestController.ingestEml(file);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertNotNull(response.getBody().emailId());
        verify(emlParserService, times(1)).parse(any(InputStream.class));
        verify(emailService, times(1)).ingestParsedEmail(parsedEmail, IngestSource.EML_API);
    }

    @Test
    void ingestEmlBatch_ShouldProcessMultipleFiles() {
        MockMultipartFile file1 = new MockMultipartFile("files", "test1.eml", "message/rfc822", "content1".getBytes());
        MockMultipartFile file2 = new MockMultipartFile("files", "test2.eml", "message/rfc822", "content2".getBytes());
        MultipartFile[] files = {file1, file2};

        IngestResponse response1 = new IngestResponse(UUID.randomUUID(), 1, EmailVerdict.ALLOW, EmailStatus.RECEIVED);
        IngestResponse response2 = new IngestResponse(UUID.randomUUID(), 2, EmailVerdict.ALLOW, EmailStatus.RECEIVED);

        when(asyncIngestService.ingestOneEmlAsync(file1))
                .thenReturn(CompletableFuture.completedFuture(response1));
        when(asyncIngestService.ingestOneEmlAsync(file2))
                .thenReturn(CompletableFuture.completedFuture(response2));

        ResponseEntity<List<BatchIngestItemResponse>> response = ingestController.ingestEmlBatch(files);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(2, response.getBody().size());
        assertTrue(response.getBody().get(0).success());
        assertTrue(response.getBody().get(1).success());
        assertEquals("test1.eml", response.getBody().get(0).filename());
        assertEquals("test2.eml", response.getBody().get(1).filename());
        verify(asyncIngestService, times(1)).ingestOneEmlAsync(file1);
        verify(asyncIngestService, times(1)).ingestOneEmlAsync(file2);
    }

    @Test
    void ingestEmlBatch_ShouldHandleFailures() {
        MockMultipartFile file = new MockMultipartFile("files", "test.eml", "message/rfc822", "content".getBytes());
        MultipartFile[] files = {file};

        CompletableFuture<IngestResponse> failedFuture = new CompletableFuture<>();
        failedFuture.completeExceptionally(new RuntimeException("Parse error"));

        when(asyncIngestService.ingestOneEmlAsync(file)).thenReturn(failedFuture);

        ResponseEntity<List<BatchIngestItemResponse>> response = ingestController.ingestEmlBatch(files);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        assertFalse(response.getBody().get(0).success());
        assertNotNull(response.getBody().get(0).error());
        assertTrue(response.getBody().get(0).error().contains("Parse error"));
    }


    @Test
    void ingestEmlBatch_ShouldHandleNullFilename() {
        MockMultipartFile file = new MockMultipartFile("files", null, "message/rfc822", "content".getBytes());
        MultipartFile[] files = {file};

        IngestResponse mockResponse = new IngestResponse(UUID.randomUUID(), 1, EmailVerdict.ALLOW, EmailStatus.RECEIVED);

        when(asyncIngestService.ingestOneEmlAsync(file))
                .thenReturn(CompletableFuture.completedFuture(mockResponse));

        ResponseEntity<List<BatchIngestItemResponse>> response = ingestController.ingestEmlBatch(files);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("unknown.eml", response.getBody().get(0).filename());
    }
}
