package com.example.emailfirewall.dto;

import com.example.emailfirewall.enums.DkimResult;
import com.example.emailfirewall.enums.DmarcPolicy;
import com.example.emailfirewall.enums.DmarcResult;
import com.example.emailfirewall.enums.SpfResult;

import java.util.ArrayList;
import java.util.List;

public class EmailAuthEvaluation {
    public SpfResult spfResult = SpfResult.NONE;
    public String spfDomain;
    public String spfSummary;

    public DkimResult dkimResult = DkimResult.NONE;
    public List<DkimSignatureEvaluation> dkimSignatures = new ArrayList<>();
    public String dkimSummary;

    public DmarcResult dmarcResult = DmarcResult.NONE;
    public DmarcPolicy dmarcPolicy = DmarcPolicy.UNKNOWN;
    public Boolean dmarcSpfAligned;
    public Boolean dmarcDkimAligned;
    public String dmarcSummary;

    public static class DkimSignatureEvaluation {
        public String domain;
        public String selector;
        public DkimResult result;
        public String summary;

        public DkimSignatureEvaluation() {}

        public DkimSignatureEvaluation(String domain, String selector, DkimResult result, String summary) {
            this.domain = domain;
            this.selector = selector;
            this.result = result;
            this.summary = summary;
        }
    }
}

