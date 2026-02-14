package com.example.emailfirewall.entity;

import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.EmailStatus;
import com.example.emailfirewall.enums.IngestSource;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.*;

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

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public IngestSource getIngestSource() {
        return ingestSource;
    }

    public void setIngestSource(IngestSource ingestSource) {
        this.ingestSource = ingestSource;
    }

    public Instant getReceivedAt() {
        return receivedAt;
    }

    public void setReceivedAt(Instant receivedAt) {
        this.receivedAt = receivedAt;
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

    public String getReplyTo() {
        return replyTo;
    }

    public void setReplyTo(String replyTo) {
        this.replyTo = replyTo;
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

    public String getMessageId() {
        return messageId;
    }

    public void setMessageId(String messageId) {
        this.messageId = messageId;
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

    public List<EmailHeaderEntity> getHeaders() {
        return headers;
    }

    public void setHeaders(List<EmailHeaderEntity> headers) {
        this.headers = headers;
    }

    public EmailStatus getStatus() {
        return status;
    }

    public void setStatus(EmailStatus status) {
        this.status = status;
    }

    public List<EmailLinkEntity> getLinks() {
        return links;
    }

    public void setLinks(List<EmailLinkEntity> links) {
        this.links = links;
    }

    public List<EmailAttachmentEntity> getAttachments() {
        return attachments;
    }

    public void setAttachments(List<EmailAttachmentEntity> attachments) {
        this.attachments = attachments;
    }

    public AuthResultsEntity getAuthResults() {
        return authResults;
    }

    public void setAuthResults(AuthResultsEntity authResults) {
        this.authResults = authResults;
    }

    public List<RuleHitEntity> getRuleHits() {
        return ruleHits;
    }

    public void setRuleHits(List<RuleHitEntity> ruleHits) {
        this.ruleHits = ruleHits;
    }
}
