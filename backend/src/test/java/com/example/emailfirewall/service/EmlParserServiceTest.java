package com.example.emailfirewall.service;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class EmlParserServiceTest {

    @Test
    void parsesAttachmentMeta_filenameAndSize() throws Exception {
        String eml = """
                From: Attach Demo <attach@example.com>
                To: Analyst <analyst@example.com>
                Subject: Attachment demo
                Date: Tue, 01 Apr 2026 17:45:00 +0300
                Message-ID: <rulehit-attach-001@example.com>
                MIME-Version: 1.0
                Content-Type: multipart/mixed; boundary=\"BOUNDARY-GETEGTW-1\"
                
                --BOUNDARY-GETEGTW-1
                Content-Type: text/plain; charset=\"UTF-8\"
                
                Hello
                
                --BOUNDARY-GETEGTW-1
                Content-Type: application/octet-stream
                Content-Disposition: attachment; filename=\"document.getegtw\"
                Content-Transfer-Encoding: base64
                
                SGVsbG8sIHRoaXMgaXMgYSBkZW1vIGF0dGFjaG1lbnQuCg==
                
                --BOUNDARY-GETEGTW-1--
                """;

        EmlParserService svc = new EmlParserService();
        var parsed = svc.parse(new ByteArrayInputStream(eml.getBytes(StandardCharsets.UTF_8)));

        assertNotNull(parsed);
        assertEquals("attach@example.com", parsed.from);
        assertNotNull(parsed.attachments);
        assertEquals(1, parsed.attachments.size());
        assertEquals("document.getegtw", parsed.attachments.get(0).filename);
        assertTrue(parsed.attachments.get(0).size > 0);
        assertNotNull(parsed.attachments.get(0).sha256);
        assertFalse(parsed.attachments.get(0).sha256.isBlank());
    }
}

