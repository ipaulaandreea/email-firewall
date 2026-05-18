package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.EmailAuthEvaluation;
import com.example.emailfirewall.enums.EmailVerdict;

import java.util.ArrayList;
import java.util.List;

public class FirewallScanResult {

    private int score;
    private EmailVerdict forcedVerdict;

    private final List<FirewallFinding> findings = new ArrayList<>();
    private final List<ScannedLink> links = new ArrayList<>();

    private EmailAuthEvaluation authEvaluation;
    private RuleEvaluationResult ruleEvaluationResult;

    public int getScore() {
        return score;
    }

    public EmailVerdict getForcedVerdict() {
        return forcedVerdict;
    }

    public List<FirewallFinding> getFindings() {
        return findings;
    }

    public List<ScannedLink> getLinks() {
        return links;
    }

    public EmailAuthEvaluation getAuthEvaluation() {
        return authEvaluation;
    }

    public void setAuthEvaluation(EmailAuthEvaluation authEvaluation) {
        this.authEvaluation = authEvaluation;
    }

    public RuleEvaluationResult getRuleEvaluationResult() {
        return ruleEvaluationResult;
    }

    public void setRuleEvaluationResult(RuleEvaluationResult ruleEvaluationResult) {
        this.ruleEvaluationResult = ruleEvaluationResult;
    }

    public void addFinding(String source, String code, int scoreDelta, String message) {
        score += scoreDelta;
        findings.add(new FirewallFinding(source, code, scoreDelta, message));
    }

    public void addLink(ScannedLink link) {
        links.add(link);
    }

    public void forceVerdict(EmailVerdict verdict) {
        forcedVerdict = verdict;
    }

    public void merge(FirewallScanResult other) {
        if (other == null) return;

        this.score += other.score;
        this.findings.addAll(other.findings);
        this.links.addAll(other.links);

        if (other.forcedVerdict != null) {
            this.forcedVerdict = other.forcedVerdict;
        }

        if (other.authEvaluation != null) {
            this.authEvaluation = other.authEvaluation;
        }

        if (other.ruleEvaluationResult != null) {
            this.ruleEvaluationResult = other.ruleEvaluationResult;
        }
    }
}