package com.example.emailfirewall.entity;

import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.EmailStatus;
import com.example.emailfirewall.enums.IngestSource;
import jakarta.persistence.*;
import lombok.Data;
import java.time.Instant;
import java.util.*;

@Data
@Entity
@Table(name = "emails", indexes = {
        @Index(name = "idx_emails_received_at", columnList = "receivedAt"),
        @Index(name = "idx_emails_verdict", columnList = "verdict"),
        @Index(name = "idx_emails_score", columnList = "threatScore")
})
public class EmailEntity {

    @Id
    private UUID id = UUID.randomUUID();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private IngestSource ingestSource;

    @Column(nullable = false)
    private Instant receivedAt = Instant.now();

    @Column(nullable = false)
    private String fromAddress;

    private String fromDomain;
    private String replyTo;

    @ElementCollection
    @CollectionTable(name = "email_recipients", joinColumns = @JoinColumn(name = "email_id"))
    @Column(name = "recipient")
    private List<String> toAddresses = new ArrayList<>();

    private String subject;

    @Column(unique = true)
    private String messageId;

    @Column(columnDefinition = "text")
    private String bodyText;

    @Column(columnDefinition = "text")
    private String bodyHtmlSanitized;

    private Long sizeBytes;

    private Integer threatScore = 0;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EmailVerdict verdict = EmailVerdict.ALLOW;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EmailStatus status = EmailStatus.RECEIVED;

    @OneToMany(mappedBy = "email", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<EmailHeaderEntity> headers = new ArrayList<>();

    @OneToMany(mappedBy = "email", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<EmailLinkEntity> links = new ArrayList<>();

    @OneToMany(mappedBy = "email", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<EmailAttachmentEntity> attachments = new ArrayList<>();

    @OneToOne(mappedBy = "email", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private AuthResultsEntity authResults;

    @OneToMany(mappedBy = "email", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<RuleHitEntity> ruleHits = new ArrayList<>();
}
