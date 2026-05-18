package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AttachmentMeta;
import com.example.emailfirewall.dto.ParsedEmail;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
public class EmlParserService {

    public ParsedEmail parse(InputStream emlStream) throws Exception {
        byte[] raw = readAll(emlStream);

        Session session = Session.getInstance(new Properties());
        MimeMessage msg = new MimeMessage(session, new java.io.ByteArrayInputStream(raw));

        ParsedEmail out = new ParsedEmail();
        out.rawEml = raw;

        Address[] from = msg.getFrom();
        if (from != null && from.length > 0) {
            out.from = addressToString(from[0]);
        }

        Address[] to = msg.getRecipients(MimeMessage.RecipientType.TO);
        if (to != null) {
            for (Address a : to) out.to.add(addressToString(a));
        }

        out.subject = msg.getSubject();

        Enumeration<?> headerLines = msg.getAllHeaderLines();
        while (headerLines.hasMoreElements()) {
            String line = headerLines.nextElement().toString();
            int idx = line.indexOf(':');
            if (idx > 0) {
                String name = line.substring(0, idx).trim();
                String value = line.substring(idx + 1).trim();

                out.headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
                out.headers.computeIfAbsent(name.toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(value);
            }
        }

        extractParts(msg, out);
        return out;
    }

    private void extractParts(Part part, ParsedEmail out) throws Exception {
        if (isAttachment(part)) {
            AttachmentMeta meta = new AttachmentMeta();
            meta.filename = safeFilename(part.getFileName());
            meta.contentType = part.getContentType();

            byte[] bytes = readAll(part.getInputStream());
            meta.size = bytes.length;
            meta.sha256 = sha256(bytes);

            out.attachments.add(meta);
            return;
        }

        if (part.isMimeType("text/plain") && out.bodyText == null) {
            out.bodyText = readText(part);
            return;
        }

        if (part.isMimeType("text/html") && out.bodyHtml == null) {
            out.bodyHtml = readText(part);
            return;
        }

        if (part.isMimeType("multipart/*")) {
            Multipart mp = (Multipart) part.getContent();
            for (int i = 0; i < mp.getCount(); i++) {
                extractParts(mp.getBodyPart(i), out);
            }
        }
    }

    private boolean isAttachment(Part part) throws Exception {
        String disposition = part.getDisposition();
        return Part.ATTACHMENT.equalsIgnoreCase(disposition)
                || Part.INLINE.equalsIgnoreCase(disposition) && part.getFileName() != null
                || part.getFileName() != null;
    }

    private String readText(Part part) throws Exception {
        Object content = part.getContent();

        if (content instanceof String s) {
            return s;
        }

        if (content instanceof InputStream is) {
            return new String(readAll(is), StandardCharsets.UTF_8);
        }

        return String.valueOf(content);
    }

    private byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        in.transferTo(buffer);
        return buffer.toByteArray();
    }

    private String sha256(byte[] bytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(bytes);

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String addressToString(Address a) {
        if (a instanceof InternetAddress ia) {
            String email = ia.getAddress();
            return email != null ? email : ia.toString();
        }
        return a.toString();
    }

    private String safeFilename(String filename) {
        if (filename == null || filename.isBlank()) return "unknown";
        return filename.replaceAll("[\\r\\n]", "").trim();
    }
}