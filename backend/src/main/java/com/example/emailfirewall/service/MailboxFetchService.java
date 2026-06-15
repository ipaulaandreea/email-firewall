package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.IngestSource;
import com.example.emailfirewall.service.EmailService;
import com.example.emailfirewall.service.EmlParserService;
import jakarta.mail.*;
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

        inbox.open(Folder.READ_WRITE);

        int total = inbox.getMessageCount();

        if (total == 0) {
            inbox.close(false);
            store.close();
            return;
        }

        int start = Math.max(1, total - limit + 1);

        Message[] messages = inbox.getMessages(start, total);

        for (Message msg : messages) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            msg.writeTo(out);

            ParsedEmail parsed = emlParserService.parse(
                    new ByteArrayInputStream(out.toByteArray())
            );

            IngestResponse response = emailService.ingestParsedEmail(parsed, IngestSource.IMAP);

            EmailVerdict verdict = response.verdict();

            if (verdict == EmailVerdict.QUARANTINE) {
                moveMessage(inbox, msg, "Quarantine");
            } else if (verdict == EmailVerdict.BLOCK) {
                moveMessage(inbox, msg, "Block");
            }
        }
        inbox.close(false);
        store.close();
    }

    private void moveMessage(Folder sourceFolder, Message message, String targetFolderName)
            throws MessagingException {

        Store store = sourceFolder.getStore();

        Folder targetFolder = ensureFolderExists(store, targetFolderName);

        sourceFolder.copyMessages(new Message[]{message}, targetFolder);

        sourceFolder.setFlags(
                new Message[]{message},
                new Flags(Flags.Flag.DELETED),
                true
        );

        sourceFolder.expunge();
    }

    private Folder ensureFolderExists(Store store, String folderName) throws MessagingException {
        Folder folder = store.getFolder(folderName);

        if (!folder.exists()) {
            boolean created = folder.create(Folder.HOLDS_MESSAGES);

            if (!created) {
                throw new MessagingException("Could not create mailbox folder: " + folderName);
            }
        }

        return store.getFolder(folderName);
    }
}