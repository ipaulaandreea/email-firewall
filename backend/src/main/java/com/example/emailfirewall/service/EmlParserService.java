package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AttachmentMeta;
import com.example.emailfirewall.dto.ParsedEmail;
import jakarta.mail.Address;
import jakarta.mail.BodyPart;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class EmlParserService {

    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3}(?:\\.\\d{1,3}){3})\\b");

    public ParsedEmail parse(InputStream emlStream) throws Exception {
        byte[] raw = readAllBytes(emlStream);
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
                out.headers
                        .computeIfAbsent(name, k -> new ArrayList<>())
                        .add(value);
            }
        }

        out.smtpClientIp = inferClientIp(out.headers.get("Received"));

        extractParts(msg, out);

        return out;
    }

    private InetAddress inferClientIp(List<String> receivedHeaders) {
        if (receivedHeaders == null || receivedHeaders.isEmpty()) return null;
        String candidate = receivedHeaders.get(receivedHeaders.size() - 1);
        Matcher m = IPV4.matcher(candidate);
        if (!m.find()) return null;
        try {
            return InetAddress.getByName(m.group(1));
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] readAllBytes(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        in.transferTo(bos);
        return bos.toByteArray();
    }

    private void extractParts(Part part, ParsedEmail out) throws Exception {
        if (part == null || out == null) return;

        if (part.isMimeType("text/plain") && out.bodyText == null) {
            out.bodyText = readText(part);
        }

        if (part.isMimeType("text/html") && out.bodyHtml == null) {
            out.bodyHtml = readText(part);
        }

        try {
            String disp = part.getDisposition();
            String filename = part.getFileName();

            boolean looksLikeAttachment =
                    Part.ATTACHMENT.equalsIgnoreCase(disp)
                            || (filename != null && !filename.isBlank());

            if (looksLikeAttachment) {
                AttachmentMeta meta = new AttachmentMeta();
                meta.filename = filename;
                meta.contentType = part.getContentType();

                byte[] bytes = readPartBytes(part);
                meta.size = bytes.length;
                meta.sha256 = sha256Hex(bytes);

                out.attachments.add(meta);
                return;
            }
        } catch (Exception ignored) {
        }

        if (part.isMimeType("multipart/*")) {
            Multipart mp = (Multipart) part.getContent();
            for (int i = 0; i < mp.getCount(); i++) {
                BodyPart bp = mp.getBodyPart(i);
                extractParts(bp, out);
            }
        }
    }

    private byte[] readPartBytes(Part part) throws Exception {
        Object content = part.getContent();
        if (content instanceof InputStream is) {
            return is.readAllBytes();
        }
        if (content instanceof String s) {
            return s.getBytes(StandardCharsets.UTF_8);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        part.getDataHandler().writeTo(bos);
        return bos.toByteArray();
    }

    private String readText(Part part) throws Exception {
        Object content = part.getContent();
        if (content instanceof String s) {
            return s;
        }
        if (content instanceof InputStream is) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
        return String.valueOf(content);
    }

    private String sha256Hex(byte[] bytes) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] dig = md.digest(bytes);
        StringBuilder sb = new StringBuilder(dig.length * 2);
        for (byte b : dig) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private String addressToString(Address a) {
        if (a instanceof InternetAddress ia) {
            String email = ia.getAddress();
            return email != null ? email : ia.toString();
        }
        return a.toString();
    }
}
