package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.EmailAuthEvaluation;
import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.enums.DkimResult;
import com.example.emailfirewall.enums.DmarcPolicy;
import com.example.emailfirewall.enums.DmarcResult;
import com.example.emailfirewall.enums.SpfResult;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class EmailAuthService {

    private final DnsTxtResolver dnsTxtResolver;

    public EmailAuthEvaluation evaluate(ParsedEmail email) {
        EmailAuthEvaluation out = new EmailAuthEvaluation();

        try {
            String fromDomain = domainOf(email != null ? email.from : null);
            out.spfDomain = fromDomain;

            InetAddress ip = email != null ? email.smtpClientIp : null;
            if (ip == null) {
                out.spfResult = SpfResult.NONE;
                out.spfSummary = "No SMTP client IP available; SPF not evaluated";
            } else if (fromDomain == null) {
                out.spfResult = SpfResult.NONE;
                out.spfSummary = "No From domain available; SPF not evaluated";
            } else {
                SpfResult hdr = parseAuthResultsSpf(email);
                if (hdr != null) {
                    out.spfResult = hdr;
                    out.spfSummary = "SPF from Authentication-Results header";
                } else {
                    boolean hasSpf = dnsTxtResolver.hasTxtStartingWith(fromDomain, "v=spf1");
                    out.spfResult = hasSpf ? SpfResult.NEUTRAL : SpfResult.NONE;
                    out.spfSummary = hasSpf ? "SPF record present (v=spf1) but not fully evaluated" : "No SPF record found";
                }
            }
        } catch (Exception e) {
            out.spfResult = SpfResult.TEMPERROR;
            out.spfSummary = "SPF evaluation error: " + e.getMessage();
        }

        try {
            DkimResult hdr = parseAuthResultsDkim(email);
            if (hdr != null) {
                out.dkimResult = hdr;
                out.dkimSummary = "DKIM from Authentication-Results header";
            } else {
                out.dkimResult = DkimResult.NONE;
                out.dkimSummary = "No DKIM verification implemented (missing Authentication-Results)";
            }
        } catch (Exception e) {
            out.dkimResult = DkimResult.TEMPERROR;
            out.dkimSummary = "DKIM evaluation error: " + e.getMessage();
        }

        try {
            String fromDomain = domainOf(email != null ? email.from : null);
            if (fromDomain == null) {
                out.dmarcResult = DmarcResult.NONE;
                out.dmarcPolicy = DmarcPolicy.UNKNOWN;
                out.dmarcSummary = "No From domain; DMARC not evaluated";
            } else {
                DmarcRecord record = DmarcRecord.parse(dnsTxtResolver.firstTxt("_dmarc." + fromDomain));
                out.dmarcPolicy = record.policy;

                boolean spfAligned = aligned(fromDomain, out.spfDomain);
                boolean dkimAligned = email != null && aligned(fromDomain, parseDkimDomainFromHeaders(email));

                out.dmarcSpfAligned = spfAligned;
                out.dmarcDkimAligned = dkimAligned;

                boolean spfPassAndAligned = out.spfResult == SpfResult.PASS && spfAligned;
                boolean dkimPassAndAligned = out.dkimResult == DkimResult.PASS && dkimAligned;

                if (record.isPresent) {
                    out.dmarcResult = (spfPassAndAligned || dkimPassAndAligned) ? DmarcResult.PASS : DmarcResult.FAIL;
                    out.dmarcSummary = "DMARC computed: spf(pass&aligned)=" + spfPassAndAligned + ", dkim(pass&aligned)=" + dkimPassAndAligned;
                } else {
                    out.dmarcResult = DmarcResult.NONE;
                    out.dmarcSummary = "No DMARC record found";
                }
            }
        } catch (Exception e) {
            out.dmarcResult = DmarcResult.NONE;
            out.dmarcPolicy = DmarcPolicy.UNKNOWN;
            out.dmarcSummary = "DMARC evaluation error: " + e.getMessage();
        }

        return out;
    }

    private static String domainOf(String addr) {
        if (addr == null) return null;
        int at = addr.lastIndexOf('@');
        if (at < 0 || at == addr.length() - 1) return null;
        return addr.substring(at + 1).trim().toLowerCase(Locale.ROOT);
    }

    private static boolean aligned(String fromDomain, String other) {
        if (fromDomain == null || other == null) return false;
        String f = fromDomain.toLowerCase(Locale.ROOT);
        String o = other.toLowerCase(Locale.ROOT);
        return f.equals(o) || f.endsWith("." + o) || o.endsWith("." + f);
    }

    private SpfResult parseAuthResultsSpf(ParsedEmail email) {
        if (email == null) return null;
        var list = email.headers.getOrDefault("Authentication-Results", email.headers.get("authentication-results"));
        if (list == null) return null;
        for (String v : list) {
            String s = v.toLowerCase(Locale.ROOT);
            int idx = s.indexOf("spf=");
            if (idx >= 0) {
                String tail = s.substring(idx + 4);
                String token = tail.split("[;\\s]", 2)[0].trim();
                return switch (token) {
                    case "pass" -> SpfResult.PASS;
                    case "fail" -> SpfResult.FAIL;
                    case "softfail" -> SpfResult.SOFTFAIL;
                    case "neutral" -> SpfResult.NEUTRAL;
                    case "none" -> SpfResult.NONE;
                    case "temperror" -> SpfResult.TEMPERROR;
                    case "permerror" -> SpfResult.PERMERROR;
                    default -> null;
                };
            }
        }
        return null;
    }

    private DkimResult parseAuthResultsDkim(ParsedEmail email) {
        if (email == null) return null;
        var list = email.headers.getOrDefault("Authentication-Results", email.headers.get("authentication-results"));
        if (list == null) return null;
        for (String v : list) {
            String s = v.toLowerCase(Locale.ROOT);
            int idx = s.indexOf("dkim=");
            if (idx >= 0) {
                String tail = s.substring(idx + 5);
                String token = tail.split("[;\\s]", 2)[0].trim();
                return switch (token) {
                    case "pass" -> DkimResult.PASS;
                    case "fail" -> DkimResult.FAIL;
                    case "none" -> DkimResult.NONE;
                    case "temperror" -> DkimResult.TEMPERROR;
                    case "permerror" -> DkimResult.PERMERROR;
                    default -> null;
                };
            }
        }
        return null;
    }

    private String parseDkimDomainFromHeaders(ParsedEmail email) {
        if (email == null) return null;
        var list = email.headers.getOrDefault("Authentication-Results", email.headers.get("authentication-results"));
        if (list == null) return null;
        for (String v : list) {
            String s = v.toLowerCase(Locale.ROOT);
            int idx = s.indexOf("header.d=");
            if (idx >= 0) {
                String tail = s.substring(idx + 9);
                return tail.split("[;\\s]", 2)[0].trim();
            }
        }
        return null;
    }

    static class DmarcRecord {
        boolean isPresent;
        DmarcPolicy policy = DmarcPolicy.UNKNOWN;

        static DmarcRecord parse(String txt) {
            DmarcRecord r = new DmarcRecord();
            if (txt == null || txt.isBlank()) return r;
            String s = txt.trim();
            if (!s.toLowerCase(Locale.ROOT).contains("v=dmarc1")) return r;
            r.isPresent = true;

            String[] parts = s.split(";");
            for (String p : parts) {
                String kv = p.trim();
                int eq = kv.indexOf('=');
                if (eq < 0) continue;
                String k = kv.substring(0, eq).trim().toLowerCase(Locale.ROOT);
                String v = kv.substring(eq + 1).trim().toLowerCase(Locale.ROOT);
                if (k.equals("p")) {
                    r.policy = switch (v) {
                        case "none" -> DmarcPolicy.NONE;
                        case "quarantine" -> DmarcPolicy.QUARANTINE;
                        case "reject" -> DmarcPolicy.REJECT;
                        default -> DmarcPolicy.UNKNOWN;
                    };
                }
            }
            return r;
        }
    }
}

