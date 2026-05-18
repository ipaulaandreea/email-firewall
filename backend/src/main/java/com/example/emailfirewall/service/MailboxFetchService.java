package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.enums.IngestSource;
import com.example.emailfirewall.service.EmailService;
import com.example.emailfirewall.service.EmlParserService;
import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Store;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Properties;

@Service

@RequiredArgsConstructor

public class MailboxFetchService {

    private final EmlParserService emlParserService;

    private final EmailService emailService;

    public void fetchInbox(String host, String username, String password, Integer limit) throws Exception {
        Properties props = new Properties();

        props.put("mail.store.protocol", "imaps");
        props.put("mail.imaps.host", host);
        props.put("mail.imaps.port", "993");
        props.put("mail.imaps.ssl.enable", "true");
        props.put("mail.imaps.auth", "true");

        Session session = Session.getInstance(props);
        session.setDebug(true);

        Store store = session.getStore("imaps");

        store.connect(
                host,
                993,
                username,
                password
        );

        Folder inbox = store.getFolder("INBOX");

        inbox.open(Folder.READ_ONLY);

        int total = inbox.getMessageCount();

        int start = Math.max(1, total - limit + 1);

        Message[] messages = inbox.getMessages(start, total);

        for (Message msg : messages) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            msg.writeTo(out);

            ParsedEmail parsed = emlParserService.parse(
                    new ByteArrayInputStream(out.toByteArray())
            );

            emailService.ingestParsedEmail(parsed, IngestSource.IMAP);
        }

        inbox.close(false);
        store.close();
    }

}