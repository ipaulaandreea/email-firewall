package com.example.emailfirewall.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "rule_hits", indexes = {
        @Index(name = "idx_rulehits_email", columnList = "email_id"),
        @Index(name = "idx_rulehits_rule", columnList = "rule_id")
})
public class RuleHitEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "email_id")
    private EmailEntity email;

    @ManyToOne(optional = false)
    @JoinColumn(name = "rule_id")
    private RuleEntity rule;

    @Column(nullable = false)
    private Instant hitAt = Instant.now();

    private Integer scoreDelta;

    @Column(columnDefinition = "text")
    private String message;

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

    public RuleEntity getRule() {
        return rule;
    }

    public void setRule(RuleEntity rule) {
        this.rule = rule;
    }

    public Instant getHitAt() {
        return hitAt;
    }

    public void setHitAt(Instant hitAt) {
        this.hitAt = hitAt;
    }

    public Integer getScoreDelta() {
        return scoreDelta;
    }

    public void setScoreDelta(Integer scoreDelta) {
        this.scoreDelta = scoreDelta;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
