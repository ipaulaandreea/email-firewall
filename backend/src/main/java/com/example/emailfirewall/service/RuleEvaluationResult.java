package com.example.emailfirewall.service;

import com.example.emailfirewall.enums.EmailVerdict;

import java.util.ArrayList;
import java.util.List;

public class RuleEvaluationResult {

    private int totalScore;
    private EmailVerdict forcedVerdict;
    private final List<String> ruleNames = new ArrayList<>();

    public int getTotalScore() {
        return totalScore;
    }

    public EmailVerdict getForcedVerdict() {
        return forcedVerdict;
    }

    public List<String> getRuleNames() {
        return ruleNames;
    }

    public void addScore(int delta, String ruleName) {
        this.totalScore += delta;
        this.ruleNames.add(ruleName);
    }

    public void forceVerdict(EmailVerdict verdict, String ruleName) {
        this.forcedVerdict = verdict;
        this.ruleNames.add(ruleName);
    }
}
