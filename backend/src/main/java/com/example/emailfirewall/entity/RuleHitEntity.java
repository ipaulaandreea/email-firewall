package com.example.emailfirewall.entity;

import com.example.emailfirewall.enums.EmailVerdict;
import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Data
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

    @Enumerated(EnumType.STRING)
    private EmailVerdict forcedVerdict;
}
