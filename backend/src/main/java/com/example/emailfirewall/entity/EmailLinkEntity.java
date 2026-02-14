package com.example.emailfirewall.entity;

import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "email_links", indexes = {
        @Index(name = "idx_links_email", columnList = "email_id"),
        @Index(name = "idx_links_host", columnList = "host")
})
public class EmailLinkEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "email_id")
    private EmailEntity email;

    @Column(columnDefinition = "text")
    private String urlRaw;

    @Column(columnDefinition = "text")
    private String urlNormalized;

    private String host;

    private Boolean isShortener = false;

    private String verdict;

    @OneToMany(mappedBy = "link", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<LinkSignalEntity> signals = new ArrayList<>();

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public EmailEntity getEmail() {
        return email;
    }

    public void setEmail(EmailEntity email) {
        this.email = email;
    }

    public String getUrlRaw() {
        return urlRaw;
    }

    public void setUrlRaw(String urlRaw) {
        this.urlRaw = urlRaw;
    }

    public String getUrlNormalized() {
        return urlNormalized;
    }

    public void setUrlNormalized(String urlNormalized) {
        this.urlNormalized = urlNormalized;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public Boolean getShortener() {
        return isShortener;
    }

    public void setShortener(Boolean shortener) {
        isShortener = shortener;
    }

    public String getVerdict() {
        return verdict;
    }

    public void setVerdict(String verdict) {
        this.verdict = verdict;
    }

    public List<LinkSignalEntity> getSignals() {
        return signals;
    }

    public void setSignals(List<LinkSignalEntity> signals) {
        this.signals = signals;
    }
}
