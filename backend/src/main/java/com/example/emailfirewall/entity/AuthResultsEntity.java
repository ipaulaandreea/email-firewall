package com.example.emailfirewall.entity;

import com.example.emailfirewall.enums.DkimResult;
import com.example.emailfirewall.enums.DmarcPolicy;
import com.example.emailfirewall.enums.DmarcResult;
import com.example.emailfirewall.enums.SpfResult;
import jakarta.persistence.*;

@Entity
@Table(name = "auth_results")
public class AuthResultsEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(optional = false)
    @JoinColumn(name = "email_id", unique = true)
    private EmailEntity email;

    @Enumerated(EnumType.STRING)
    private SpfResult spfResult;

    @Enumerated(EnumType.STRING)
    private DkimResult dkimResult;

    @Enumerated(EnumType.STRING)
    private DmarcResult dmarcResult;

    @Enumerated(EnumType.STRING)
    private DmarcPolicy dmarcPolicy;

    @Column(columnDefinition = "jsonb")
    private String detailsJson;

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

    public SpfResult getSpfResult() {
        return spfResult;
    }

    public void setSpfResult(SpfResult spfResult) {
        this.spfResult = spfResult;
    }

    public DkimResult getDkimResult() {
        return dkimResult;
    }

    public void setDkimResult(DkimResult dkimResult) {
        this.dkimResult = dkimResult;
    }

    public DmarcResult getDmarcResult() {
        return dmarcResult;
    }

    public void setDmarcResult(DmarcResult dmarcResult) {
        this.dmarcResult = dmarcResult;
    }

    public DmarcPolicy getDmarcPolicy() {
        return dmarcPolicy;
    }

    public void setDmarcPolicy(DmarcPolicy dmarcPolicy) {
        this.dmarcPolicy = dmarcPolicy;
    }

    public String getDetailsJson() {
        return detailsJson;
    }

    public void setDetailsJson(String detailsJson) {
        this.detailsJson = detailsJson;
    }
}
