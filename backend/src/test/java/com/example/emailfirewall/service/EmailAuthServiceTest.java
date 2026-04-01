package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.enums.DkimResult;
import com.example.emailfirewall.enums.DmarcPolicy;
import com.example.emailfirewall.enums.DmarcResult;
import com.example.emailfirewall.enums.SpfResult;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.*;

class EmailAuthServiceTest {

    static class StubDnsTxtResolver extends DnsTxtResolver {
        private final String dmarc;
        private final boolean hasSpf;

        StubDnsTxtResolver(String dmarc, boolean hasSpf) {
            this.dmarc = dmarc;
            this.hasSpf = hasSpf;
        }

        @Override
        public String firstTxt(String name) {
            if (name != null && name.toLowerCase().startsWith("_dmarc.")) return dmarc;
            return hasSpf ? "v=spf1 -all" : null;
        }

        @Override
        public boolean hasTxtStartingWith(String domain, String prefixLowerCase) {
            return hasSpf;
        }
    }

    @Test
    void parsesAuthenticationResults_spfDkimAndComputesDmarc() throws Exception {
        EmailAuthService svc = new EmailAuthService(new StubDnsTxtResolver("v=DMARC1; p=reject;", true));

        ParsedEmail p = new ParsedEmail();
        p.from = "alice@example.com";
        p.smtpClientIp = InetAddress.getByName("203.0.113.5");
        p.headers.put("Authentication-Results", java.util.List.of(
                "mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com"
        ));

        var eval = svc.evaluate(p);

        assertEquals(SpfResult.PASS, eval.spfResult);
        assertEquals(DkimResult.PASS, eval.dkimResult);
        assertEquals(DmarcPolicy.REJECT, eval.dmarcPolicy);
        assertEquals(DmarcResult.PASS, eval.dmarcResult);
        assertTrue(eval.dmarcDkimAligned);
    }

    @Test
    void dmarcFailWithRejectPolicy() throws Exception {
        EmailAuthService svc = new EmailAuthService(new StubDnsTxtResolver("v=DMARC1; p=reject;", true));

        ParsedEmail p = new ParsedEmail();
        p.from = "alice@example.com";
        p.smtpClientIp = InetAddress.getByName("203.0.113.5");
        p.headers.put("Authentication-Results", java.util.List.of(
                "mx.example.net; spf=fail smtp.mailfrom=evil.com; dkim=fail header.d=evil.com"
        ));

        var eval = svc.evaluate(p);

        assertEquals(SpfResult.FAIL, eval.spfResult);
        assertEquals(DkimResult.FAIL, eval.dkimResult);
        assertEquals(DmarcPolicy.REJECT, eval.dmarcPolicy);
        assertEquals(DmarcResult.FAIL, eval.dmarcResult);
    }
}

