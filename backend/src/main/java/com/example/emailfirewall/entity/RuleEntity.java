package com.example.emailfirewall.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

import com.example.emailfirewall.enums.RuleType;
import com.example.emailfirewall.enums.RuleAction;
import com.example.emailfirewall.enums.RuleTarget;
import com.example.emailfirewall.enums.EmailVerdict;

@Entity
@Table(name = "rules", indexes = {
        @Index(name = "idx_rules_enabled", columnList = "enabled"),
        @Index(name = "idx_rules_priority", columnList = "priority")
})
public class RuleEntity {

    @Id
    private UUID id = UUID.randomUUID();

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RuleType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RuleTarget target;

    @Column(columnDefinition = "text")
    private String pattern;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RuleAction action;

    private Integer scoreDelta;

    @Enumerated(EnumType.STRING)
    private EmailVerdict verdict;

    @Column(nullable = false)
    private Boolean enabled = true;

    @Column(nullable = false)
    private Integer priority = 100;

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public RuleType getType() {
        return type;
    }

    public void setType(RuleType type) {
        this.type = type;
    }

    public RuleTarget getTarget() {
        return target;
    }

    public void setTarget(RuleTarget target) {
        this.target = target;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public RuleAction getAction() {
        return action;
    }

    public void setAction(RuleAction action) {
        this.action = action;
    }

    public Integer getScoreDelta() {
        return scoreDelta;
    }

    public void setScoreDelta(Integer scoreDelta) {
        this.scoreDelta = scoreDelta;
    }

    public EmailVerdict getVerdict() {
        return verdict;
    }

    public void setVerdict(EmailVerdict verdict) {
        this.verdict = verdict;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Integer getPriority() {
        return priority;
    }

    public void setPriority(Integer priority) {
        this.priority = priority;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
