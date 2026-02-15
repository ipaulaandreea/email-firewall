package com.example.emailfirewall.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ParsedEmail {
    public String from;
    public List<String> to = new ArrayList<>();
    public String subject;
    public String bodyText;
    public String bodyHtml;
    public Map<String, String> headers = new HashMap<>();
}
