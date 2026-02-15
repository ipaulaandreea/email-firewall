package com.example.emailfirewall.service;

import jakarta.mail.Address;
import jakarta.mail.BodyPart;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.Properties;

@Service
public class EmlParserService {

    public ParsedEmail parse(InputStream emlStream) throws Exception {
        Session session = Session.getInstance(new Properties());
        MimeMessage msg = new MimeMessage(session, emlStream);

        ParsedEmail out = new ParsedEmail();

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
                out.headers.merge(name, value, (a, b) -> a + "; " + b);
            }
        }

        extractBody(msg, out);

        return out;
    }

    private void extractBody(Part part, ParsedEmail out) throws Exception {
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
                BodyPart bp = mp.getBodyPart(i);
                extractBody(bp, out);
            }
        }
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

    private String addressToString(Address a) {
        if (a instanceof InternetAddress ia) {
            String email = ia.getAddress();
            return email != null ? email : ia.toString();
        }
        return a.toString();
    }
}
