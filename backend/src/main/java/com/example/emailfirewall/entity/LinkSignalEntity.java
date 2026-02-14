package com.example.emailfirewall.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "link_signals", indexes = {
        @Index(name = "idx_signals_link", columnList = "link_id")
})
public class LinkSignalEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "link_id")
    private EmailLinkEntity link;

    private String signalType;
    private String severity;
    private Integer scoreDelta;

    @Column(columnDefinition = "text")
    private String details;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public EmailLinkEntity getLink() {
        return link;
    }

    public void setLink(EmailLinkEntity link) {
        this.link = link;
    }

    public String getSignalType() {
        return signalType;
    }

    public void setSignalType(String signalType) {
        this.signalType = signalType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Integer getScoreDelta() {
        return scoreDelta;
    }

    public void setScoreDelta(Integer scoreDelta) {
        this.scoreDelta = scoreDelta;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}
