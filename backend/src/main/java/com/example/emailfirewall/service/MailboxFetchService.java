package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.IngestResponse;
import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.enums.EmailStatus;
import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.IngestSource;
import com.example.emailfirewall.repository.EmailRepository;
import jakarta.mail.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class MailboxFetchService {

    private static final int DEFAULT_LIMIT = 10;

    private final EmlParserService emlParserService;
    private final EmailService emailService;
    private final EmailRepository emailRepository;

    private final Map<String, MoveTarget> movableMessages = new ConcurrentHashMap<>();

    private record MoveTarget(UUID emailId, String folder) {}

    public void analyzeInbox(String host, String username, String password, Integer limit) throws Exception {
        String appUser = currentUsername();

        Store store = null;
        Folder inbox = null;

        try {
            Session session = Session.getInstance(buildProps(host));
            store = session.getStore("imaps");
            store.connect(host, 993, username, password);

            inbox = store.getFolder("INBOX");
            inbox.open(Folder.READ_ONLY);

            int total = inbox.getMessageCount();
            if (total == 0) return;

            int effectiveLimit = resolveLimit(limit);
            int start = Math.max(1, total - effectiveLimit + 1);

            Message[] messages = inbox.getMessages(start, total);

            for (Message msg : messages) {
                String messageId = getMessageId(msg);
                String moveKey = moveKey(appUser, messageId);

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                msg.writeTo(out);

                ParsedEmail parsed = emlParserService.parse(
                        new ByteArrayInputStream(out.toByteArray())
                );

                IngestResponse response = emailService.ingestParsedEmail(parsed, IngestSource.IMAP);
                EmailVerdict verdict = response.verdict();

                if (verdict == EmailVerdict.QUARANTINE) {
                    movableMessages.put(moveKey, new MoveTarget(response.emailId(), "Quarantined"));
                } else if (verdict == EmailVerdict.BLOCK) {
                    movableMessages.put(moveKey, new MoveTarget(response.emailId(), "Blocked"));
                } else {
                    movableMessages.remove(moveKey);
                }
            }
        } finally {
            if (inbox != null && inbox.isOpen()) {
                inbox.close(false);
            }
            if (store != null && store.isConnected()) {
                store.close();
            }
        }
    }

    public int fetchAndMoveInbox(String host, String username, String password, Integer limit) throws Exception {
        String appUser = currentUsername();

        Store store = null;
        Folder inbox = null;
        int moved = 0;

        try {
            Session session = Session.getInstance(buildProps(host));
            store = session.getStore("imaps");
            ensureFolderExists(store, "Quarantine");
            ensureFolderExists(store, "Block");
            store.connect(host, 993, username, password);

            inbox = store.getFolder("INBOX");
            inbox.open(Folder.READ_WRITE);

            int total = inbox.getMessageCount();
            if (total == 0 || movableMessages.isEmpty()) return 0;

            int effectiveLimit = resolveLimit(limit);
            int start = Math.max(1, total - effectiveLimit + 1);

            Message[] messages = inbox.getMessages(start, total);

            for (Message msg : messages) {
                String messageId = getMessageId(msg);
                String moveKey = moveKey(appUser, messageId);

                MoveTarget target = movableMessages.get(moveKey);
                if (target == null) continue;

                moveMessage(inbox, msg, target.folder());

                emailRepository.findById(target.emailId()).ifPresent(email -> {
                    email.setStatus(EmailStatus.QUARANTINED);
                    email.setMailboxFolder(target.folder());
                    emailRepository.save(email);
                });

                movableMessages.remove(moveKey);
                moved++;
            }

            return moved;
        } finally {
            if (inbox != null && inbox.isOpen()) {
                inbox.close(true);
            }
            if (store != null && store.isConnected()) {
                store.close();
            }
        }
    }

    private Properties buildProps(String host) {
        Properties props = new Properties();
        props.put("mail.store.protocol", "imaps");
        props.put("mail.imaps.host", host);
        props.put("mail.imaps.port", "993");
        props.put("mail.imaps.ssl.enable", "true");
        props.put("mail.imaps.auth", "true");
        return props;
    }

    private int resolveLimit(Integer limit) {
        return (limit == null || limit <= 0) ? DEFAULT_LIMIT : limit;
    }

    private String getMessageId(Message message) throws MessagingException {
        String[] headers = message.getHeader("Message-ID");

        if (headers != null && headers.length > 0 && headers[0] != null && !headers[0].isBlank()) {
            return headers[0].trim();
        }

        return String.valueOf(message.getMessageNumber());
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
    }

    private Folder ensureFolderExists(Store store, String folderName) throws MessagingException {
        Folder folder = store.getFolder(folderName);

        if (folder.exists()) {
            return folder;
        }

        boolean created = folder.create(Folder.HOLDS_MESSAGES);

        if (!created) {
            throw new MessagingException("Could not create Gmail label: " + folderName);
        }

        folder.setSubscribed(true);

        for (int i = 0; i < 10; i++) {
            Folder refreshed = store.getFolder(folderName);

            if (refreshed.exists()) {
                return refreshed;
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new MessagingException("Interrupted while waiting for Gmail label creation", e);
            }
        }

        throw new MessagingException("Gmail label was created but is not visible yet: " + folderName);
    }

    private String currentUsername() {
        var auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth.getName() == null || auth.getName().isBlank()) {
            return "anonymous";
        }

        return auth.getName();
    }

    private String moveKey(String appUser, String messageId) {
        return appUser + ":" + messageId;
    }
}