package com.example.emailfirewall.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

import com.example.emailfirewall.enums.RuleAction;
import com.example.emailfirewall.enums.RuleTarget;
import com.example.emailfirewall.enums.EmailVerdict;
import lombok.Data;

@Entity
@Data
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
}
