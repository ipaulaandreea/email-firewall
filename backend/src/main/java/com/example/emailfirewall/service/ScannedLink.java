package com.example.emailfirewall.service;

import java.util.ArrayList;
import java.util.List;

public class ScannedLink {
    public String urlRaw;
    public String urlNormalized;
    public String host;
    public boolean shortener;
    public String verdict = "CLEAN";
    public List<FirewallFinding> signals = new ArrayList<>();
}