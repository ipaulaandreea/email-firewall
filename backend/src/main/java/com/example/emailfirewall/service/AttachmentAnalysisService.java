package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AttachmentMeta;
import com.example.emailfirewall.dto.ParsedEmail;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Set;

@Service
public class AttachmentAnalysisService {

    private static final long LARGE_ATTACHMENT = 10L * 1024 * 1024;

    private static final Set<String> DANGEROUS = Set.of(
            "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js",
            "jar", "ps1", "msi", "hta", "lnk", "reg", "dll"
    );

    private static final Set<String> SUSPICIOUS = Set.of(
            "zip", "rar", "7z", "iso", "img", "docm", "xlsm", "pptm", "rtf"
    );

    public FirewallScanResult analyze(ParsedEmail email) {
        FirewallScanResult result = new FirewallScanResult();

        if (email == null || email.attachments == null) return result;

        for (AttachmentMeta a : email.attachments) {
            String filename = a.filename != null ? a.filename : "unknown";
            String ext = extension(filename);

            if (DANGEROUS.contains(ext)) {
                result.addFinding("ATTACHMENT", "DANGEROUS_EXTENSION", 70,
                        "Atașament periculos: " + filename);
            } else if (SUSPICIOUS.contains(ext)) {
                result.addFinding("ATTACHMENT", "SUSPICIOUS_EXTENSION", 25,
                        "Atașament suspect: " + filename);
            }

            if (a.size >= LARGE_ATTACHMENT) {
                result.addFinding("ATTACHMENT", "LARGE_ATTACHMENT", 15,
                        "Atașament mare: " + filename);
            }

            if (hasDoubleExtension(filename)) {
                result.addFinding("ATTACHMENT", "DOUBLE_EXTENSION", 35,
                        "Atașament cu extensie dublă: " + filename);
            }
        }

        return result;
    }

    public String verdictFor(AttachmentMeta a) {
        String filename = a.filename != null ? a.filename : "";
        String ext = extension(filename);

        if (DANGEROUS.contains(ext) || hasDoubleExtension(filename)) return "SUSPICIOUS";
        if (SUSPICIOUS.contains(ext)) return "WARNING";
        return "CLEAN";
    }

    public String extension(String filename) {
        int idx = filename.lastIndexOf('.');
        if (idx < 0 || idx == filename.length() - 1) return "";
        return filename.substring(idx + 1).toLowerCase(Locale.ROOT);
    }

    private boolean hasDoubleExtension(String filename) {
        String lower = filename.toLowerCase(Locale.ROOT);
        return lower.matches(".*\\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt)\\.(exe|scr|bat|cmd|js|vbs|ps1)$");
    }
}