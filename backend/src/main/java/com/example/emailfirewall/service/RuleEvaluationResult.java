package com.example.emailfirewall.service;

import com.example.emailfirewall.entity.RuleEntity;
import com.example.emailfirewall.enums.EmailVerdict;

import java.util.ArrayList;
import java.util.List;

public class RuleEvaluationResult {

    public record RuleHit(
            RuleEntity rule,
            Integer scoreDelta,
            EmailVerdict forcedVerdict,
            String message
    ) {}

    private int totalScore;
    private EmailVerdict forcedVerdict;
    private final List<RuleHit> hits = new ArrayList<>();
    private boolean bypassTriggered;

    public boolean isBypassTriggered() {
        return bypassTriggered;
    }

    public void triggerBypass(RuleEntity rule, String message) {
        bypassTriggered = true;
        hits.add(new RuleHit(rule, 0, null, message));
    }


    public int getTotalScore() {
        return totalScore;
    }

    public EmailVerdict getForcedVerdict() {
        return forcedVerdict;
    }

    public List<RuleHit> getHits() {
        return hits;
    }

    public void addScore(int delta, RuleEntity rule, String message) {
        totalScore += delta;
        hits.add(new RuleHit(rule, delta, null, message));
    }

    public void forceVerdict(EmailVerdict verdict, RuleEntity rule, String message) {
        forcedVerdict = verdict;
        hits.add(new RuleHit(rule, null, verdict, message));
    }
}