package com.example.emailfirewall.entity;

import com.example.emailfirewall.enums.EmailStatus;
import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.IngestSource;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "emails")
public class EmailEntity {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Setter
    @Column(nullable = false)
    private Instant receivedAt = Instant.now();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private IngestSource ingestSource;

    @Column(nullable = false, length = 320)
    private String fromAddress;

    @Column(length = 255)
    private String fromDomain;

    @ElementCollection
    @CollectionTable(
            name = "email_to_addresses",
            joinColumns = @JoinColumn(name = "email_id")
    )
    @Column(name = "to_address", nullable = false, length = 320)
    private List<String> toAddresses = new ArrayList<>();

    @Column(length = 998)
    private String subject;

    @Column(columnDefinition = "TEXT")
    private String bodyText;

    @Column(columnDefinition = "TEXT")
    private String bodyHtmlSanitized;

    @Column
    private Long sizeBytes;

    @Column(nullable = false)
    private Integer threatScore = 0;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private EmailVerdict verdict = EmailVerdict.ALLOW;

    @Setter
    @Getter
    @Column(name = "ai_spam_score")
    private Integer aiSpamScore;

    @Setter
    @Getter
    @Column(name = "ai_classification")
    private String aiClassification;

    @Setter
    @Getter
    @Column(name = "ai_explanation", length = 4000)
    private String aiExplanation;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private EmailStatus status = EmailStatus.ANALYZED;

    @Setter
    @Getter
    @Column(name = "imap_uid")
    private Long imapUid;

    @Setter
    @Getter
    @Column(name = "mailbox_folder", length = 255)
    private String mailboxFolder;

    @Setter
    @Getter
    @Column(name = "mailbox_provider", length = 64)
    private String mailboxProvider;

    @Setter
    @Getter
    @Column(name = "mailbox_username", length = 320)
    private String mailboxUsername;

    @OneToMany(
            mappedBy = "email",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<EmailHeaderEntity> headers = new ArrayList<>();

    @OneToMany(
            mappedBy = "email",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<EmailAttachmentEntity> attachments = new ArrayList<>();

    @OneToMany(
            mappedBy = "email",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<EmailLinkEntity> links = new ArrayList<>();

    @OneToMany(
            mappedBy = "email",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    private List<RuleHitEntity> ruleHits = new ArrayList<>();

    @OneToOne(
            mappedBy = "email",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private AuthResultsEntity authResults;

    public EmailEntity() {
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Instant getReceivedAt() {
        return receivedAt;
    }

    public IngestSource getIngestSource() {
        return ingestSource;
    }

    public void setIngestSource(IngestSource ingestSource) {
        this.ingestSource = ingestSource;
    }

    public String getFromAddress() {
        return fromAddress;
    }

    public void setFromAddress(String fromAddress) {
        this.fromAddress = fromAddress;
    }

    public String getFromDomain() {
        return fromDomain;
    }

    public void setFromDomain(String fromDomain) {
        this.fromDomain = fromDomain;
    }

    public List<String> getToAddresses() {
        return toAddresses;
    }

    public void setToAddresses(List<String> toAddresses) {
        this.toAddresses = toAddresses;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getBodyText() {
        return bodyText;
    }

    public void setBodyText(String bodyText) {
        this.bodyText = bodyText;
    }

    public String getBodyHtmlSanitized() {
        return bodyHtmlSanitized;
    }

    public void setBodyHtmlSanitized(String bodyHtmlSanitized) {
        this.bodyHtmlSanitized = bodyHtmlSanitized;
    }

    public Long getSizeBytes() {
        return sizeBytes;
    }

    public void setSizeBytes(Long sizeBytes) {
        this.sizeBytes = sizeBytes;
    }

    public Integer getThreatScore() {
        return threatScore;
    }

    public void setThreatScore(Integer threatScore) {
        this.threatScore = threatScore;
    }

    public EmailVerdict getVerdict() {
        return verdict;
    }

    public void setVerdict(EmailVerdict verdict) {
        this.verdict = verdict;
    }

    public EmailStatus getStatus() {
        return status;
    }

    public void setStatus(EmailStatus status) {
        this.status = status;
    }

    public List<EmailHeaderEntity> getHeaders() {
        return headers;
    }

    public void setHeaders(List<EmailHeaderEntity> headers) {
        this.headers = headers;
    }

    public List<EmailAttachmentEntity> getAttachments() {
        return attachments;
    }

    public void setAttachments(List<EmailAttachmentEntity> attachments) {
        this.attachments = attachments;
    }

    public List<EmailLinkEntity> getLinks() {
        return links;
    }

    public void setLinks(List<EmailLinkEntity> links) {
        this.links = links;
    }

    public List<RuleHitEntity> getRuleHits() {
        return ruleHits;
    }

    public void setRuleHits(List<RuleHitEntity> ruleHits) {
        this.ruleHits = ruleHits;
    }

    public AuthResultsEntity getAuthResults() {
        return authResults;
    }

    public void setAuthResults(AuthResultsEntity authResults) {
        this.authResults = authResults;
    }

    @PrePersist
    public void prePersist() {
        if (receivedAt == null) {
            receivedAt = Instant.now();
        }

        if (threatScore == null) {
            threatScore = 0;
        }

        if (verdict == null) {
            verdict = EmailVerdict.ALLOW;
        }

        if (status == null) {
            status = EmailStatus.ANALYZED;
        }

        if (toAddresses == null) {
            toAddresses = new ArrayList<>();
        }

        if (headers == null) {
            headers = new ArrayList<>();
        }

        if (attachments == null) {
            attachments = new ArrayList<>();
        }

        if (links == null) {
            links = new ArrayList<>();
        }

        if (ruleHits == null) {
            ruleHits = new ArrayList<>();
        }
    }
}