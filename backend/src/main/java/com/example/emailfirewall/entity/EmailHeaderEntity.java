package com.example.emailfirewall.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "email_headers", indexes = {
        @Index(name = "idx_headers_email", columnList = "email_id"),
        @Index(name = "idx_headers_name", columnList = "name")
})
public class EmailHeaderEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "email_id")
    private EmailEntity email;

    @Column(nullable = false)
    private String name;

    @Column(columnDefinition = "text")
    private String value;

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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
