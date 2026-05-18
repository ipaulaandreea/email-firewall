package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.ParsedEmail;
import org.springframework.stereotype.Service;

import java.net.IDN;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UrlAnalysisService {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://[^\\s\"'<>]+)",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern HREF_PATTERN =
            Pattern.compile("href\\s*=\\s*['\"]([^'\"]+)['\"]",
                    Pattern.CASE_INSENSITIVE);

    private static final Pattern IP_HOST = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"
    );

    public FirewallScanResult analyze(ParsedEmail email) {

        FirewallScanResult result = new FirewallScanResult();

        if (email == null) {

            return result;

        }

        String content = safe(email.bodyText) + "\n" + safe(email.bodyHtml);

        // 1. URL-uri plain text din bodyText/bodyHtml

        Matcher urlMatcher = URL_PATTERN.matcher(content);

        while (urlMatcher.find()) {

            String raw = cleanup(urlMatcher.group(1));

            analyzeUrl(raw, result);

        }

        // 2. URL-uri din href="..."

        Pattern hrefPattern = Pattern.compile(

                "href\\s*=\\s*[\"']([^\"']+)[\"']",

                Pattern.CASE_INSENSITIVE

        );

        Matcher hrefMatcher = hrefPattern.matcher(content);

        while (hrefMatcher.find()) {

            String raw = cleanup(hrefMatcher.group(1));

            if (raw.startsWith("http://") || raw.startsWith("https://")) {

                analyzeUrl(raw, result);

            }

        }

        // 3. Detectare mismatch între href și textul vizibil

        detectHrefMismatch(email, result);

        // 4. Deduplicare linkuri după URL normalizat

        deduplicateLinks(result);

        return result;

    }

    private void deduplicateLinks(FirewallScanResult result) {
        if (result == null || result.getLinks() == null || result.getLinks().isEmpty()) {
            return;
        }

        Map<String, ScannedLink> unique = new LinkedHashMap<>();

        for (ScannedLink link : result.getLinks()) {
            if (link == null) continue;

            String key = link.urlNormalized != null && !link.urlNormalized.isBlank()
                    ? link.urlNormalized
                    : link.urlRaw;

            if (key == null || key.isBlank()) continue;

            ScannedLink existing = unique.get(key);

            if (existing == null) {
                unique.put(key, link);
                continue;
            }

            existing.verdict = moreSevere(existing.verdict, link.verdict);

            if (link.shortener) {
                existing.shortener = true;
            }

            if (existing.host == null && link.host != null) {
                existing.host = link.host;
            }

            if (link.signals != null && !link.signals.isEmpty()) {
                existing.signals.addAll(link.signals);
            }
        }

        result.getLinks().clear();
        result.getLinks().addAll(unique.values());
    }

    private String moreSevere(String a, String b) {
        return severityRank(b) > severityRank(a) ? b : a;
    }

    private int severityRank(String verdict) {
        if (verdict == null) return 0;

        return switch (verdict.toUpperCase()) {
            case "SUSPICIOUS" -> 3;
            case "WARNING" -> 2;
            case "CLEAN" -> 1;
            default -> 0;
        };
    }

    private void analyzeUrl(String raw, FirewallScanResult result) {
        ScannedLink link = new ScannedLink();
        link.urlRaw = raw;
        link.urlNormalized = raw;

        try {
            URI uri = URI.create(raw);
            String host = uri.getHost();

            if (host == null) return;

            host = host.toLowerCase(Locale.ROOT);
            link.host = host;

            if (SHORTENERS.contains(host)) {
                addSignal(result, link, "URL_SHORTENER", 25,
                        "URL shortener detectat: " + raw);
                link.shortener = true;
            }

            if (IP_HOST.matcher(host).matches()) {
                addSignal(result, link, "IP_HOST_URL", 35,
                        "URL cu IP direct: " + raw);
            }

            if (host.startsWith("xn--") || host.contains(".xn--")) {
                addSignal(result, link, "PUNYCODE_DOMAIN", 40,
                        "Domeniu punycode/homograph: " + raw);
            }

            String unicodeHost = IDN.toUnicode(host);
            if (!unicodeHost.equals(host)) {
                addSignal(result, link, "IDN_DOMAIN", 20,
                        "Domeniu internaționalizat: " + unicodeHost);
            }

            if (raw.length() > 180) {
                addSignal(result, link, "VERY_LONG_URL", 15,
                        "URL foarte lung detectat");
            }

            if (!link.signals.isEmpty()) {
                link.verdict = maxVerdict(link);
            }

            result.addLink(link);

        } catch (Exception e) {
            result.addFinding("URL", "MALFORMED_URL", 20,
                    "URL invalid sau malformat: " + raw);
        }
    }

    private void detectHrefMismatch(ParsedEmail email, FirewallScanResult result) {
        if (email == null || email.bodyHtml == null) return;

        Pattern hrefPattern = Pattern.compile(
                "<a[^>]+href=[\"'](https?://[^\"']+)[\"'][^>]*>(.*?)</a>",
                Pattern.CASE_INSENSITIVE | Pattern.DOTALL
        );

        Matcher m = hrefPattern.matcher(email.bodyHtml);

        while (m.find()) {
            String href = cleanup(m.group(1));
            String label = stripHtml(m.group(2));

            Matcher visibleUrlMatcher = URL_PATTERN.matcher(label);
            if (!visibleUrlMatcher.find()) continue;

            String visibleUrl = cleanup(visibleUrlMatcher.group(1));

            try {
                String hrefHost = URI.create(href).getHost();
                String visibleHost = URI.create(visibleUrl).getHost();

                if (hrefHost != null
                        && visibleHost != null
                        && !hrefHost.equalsIgnoreCase(visibleHost)) {

                    ScannedLink link = new ScannedLink();
                    link.urlRaw = href;
                    link.urlNormalized = href;
                    link.host = hrefHost.toLowerCase(Locale.ROOT);
                    link.verdict = "SUSPICIOUS";

                    FirewallFinding finding = new FirewallFinding(
                            "URL",
                            "HREF_MISMATCH",
                            45,
                            "Link înșelător: textul arată " + visibleHost
                                    + ", dar href merge către " + hrefHost
                    );

                    link.signals.add(finding);
                    result.addFinding(
                            finding.source(),
                            finding.code(),
                            finding.scoreDelta(),
                            finding.message()
                    );
                    result.addLink(link);
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void addSignal(
            FirewallScanResult result,
            ScannedLink link,
            String code,
            int score,
            String message
    ) {
        FirewallFinding finding = new FirewallFinding("URL", code, score, message);

        link.signals.add(finding);
        result.addFinding(
                finding.source(),
                finding.code(),
                finding.scoreDelta(),
                finding.message()
        );
    }

    private String maxVerdict(ScannedLink link) {
        int max = link.signals.stream()
                .mapToInt(FirewallFinding::scoreDelta)
                .max()
                .orElse(0);

        if (max >= 35) return "SUSPICIOUS";
        if (max >= 15) return "WARNING";
        return "CLEAN";
    }

    private String cleanup(String url) {
        if (url == null) return "";
        return url.replaceAll("[),.;]+$", "");
    }

    private String stripHtml(String html) {
        if (html == null) return "";
        return html.replaceAll("<[^>]+>", " ");
    }

    private String safe(String s) {
        return s == null ? "" : s;
    }
}