package com.example.emailfirewall.service;

import com.example.emailfirewall.dto.AttachmentMeta;
import com.example.emailfirewall.dto.ParsedEmail;
import com.example.emailfirewall.entity.RuleEntity;
import com.example.emailfirewall.enums.EmailVerdict;
import com.example.emailfirewall.enums.RuleAction;
import com.example.emailfirewall.enums.RuleTarget;
import com.example.emailfirewall.repository.RuleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RuleEvaluationServiceTest {

    private RuleRepository ruleRepository;
    private RuleEvaluationService service;

    @BeforeEach
    void setUp() {
        ruleRepository = mock(RuleRepository.class);
        service = new RuleEvaluationService(ruleRepository);
    }

    private static RuleEntity mockRule(
            UUID id,
            String name,
            boolean enabled,
            RuleTarget target,
            RuleAction action,
            String pattern,
            Integer scoreDelta,
            EmailVerdict verdict
    ) {
        RuleEntity r = mock(RuleEntity.class);

        when(r.getId()).thenReturn(id);
        when(r.getName()).thenReturn(name);
        when(r.getEnabled()).thenReturn(enabled);
        when(r.getTarget()).thenReturn(target);
        when(r.getAction()).thenReturn(action);
        when(r.getPattern()).thenReturn(pattern);
        when(r.getScoreDelta()).thenReturn(scoreDelta);
        when(r.getVerdict()).thenReturn(verdict);

        return r;
    }

    private static ParsedEmail baseEmail(String from, String subject, String bodyText, String bodyHtml) {
        ParsedEmail e = new ParsedEmail();
        e.from = from;
        e.subject = subject;
        e.bodyText = bodyText;
        e.bodyHtml = bodyHtml;
        return e;
    }

    @Test
    void whitelistBeatsBlacklist_evenIfBlacklistAppearsFirstInList() {
        RuleEntity blacklist = mockRule(
                UUID.randomUUID(),
                "Blacklist evil.com",
                true,
                RuleTarget.SENDER_DOMAIN,
                RuleAction.SET_VERDICT,
                "evil.com",
                null,
                EmailVerdict.BLOCK
        );

        RuleEntity whitelist = mockRule(
                UUID.randomUUID(),
                "Whitelist trusted.com",
                true,
                RuleTarget.SENDER_DOMAIN,
                RuleAction.BYPASS,
                "trusted.com",
                null,
                null
        );

        when(ruleRepository.findByEnabledTrueOrderByPriorityAsc()).thenReturn(List.of(blacklist, whitelist));

        ParsedEmail email = baseEmail("user@trusted.com", "hi", "body", null);

        RuleEvaluationResult res = service.evaluate(email);

        assertEquals(EmailVerdict.ALLOW, res.getForcedVerdict(), "Whitelist should force ALLOW");
        assertTrue(res.getHits().size() >= 1, "Should have at least one hit recorded");
        assertEquals(0, res.getTotalScore(), "Whitelist should not necessarily add score");
        verify(ruleRepository).findByEnabledTrueOrderByPriorityAsc();
    }

    @Test
    void blacklistBlocks_whenNoWhitelistMatches() {
        RuleEntity blacklist = mockRule(
                UUID.randomUUID(),
                "Blacklist evil.com",
                true,
                RuleTarget.SENDER_DOMAIN,
                RuleAction.SET_VERDICT,
                "evil.com",
                null,
                EmailVerdict.BLOCK
        );

        when(ruleRepository.findByEnabledTrueOrderByPriorityAsc()).thenReturn(List.of(blacklist));

        ParsedEmail email = baseEmail("a@sub.evil.com", "hello", "text", null);

        RuleEvaluationResult res = service.evaluate(email);

        assertEquals(EmailVerdict.BLOCK, res.getForcedVerdict());
        assertEquals(1, res.getHits().size());
        assertNotNull(res.getHits().get(0).getMessage());
    }

    @Test
    void addScoreAggregates_multipleMatchingRules_subjectAndBody() {
        RuleEntity scoreSubject = mockRule(
                UUID.randomUUID(),
                "Invoice regex",
                true,
                RuleTarget.SUBJECT,
                RuleAction.ADD_SCORE,
                "invoice\\s+overdue",
                40,
                null
        );

        RuleEntity scoreBodyKeyword = mockRule(
                UUID.randomUUID(),
                "Urgent keyword",
                true,
                RuleTarget.BODY,
                RuleAction.ADD_SCORE,
                "kw:urgent payment",
                30,
                null
        );

        when(ruleRepository.findByEnabledTrueOrderByPriorityAsc()).thenReturn(List.of(scoreSubject, scoreBodyKeyword));

        ParsedEmail email = baseEmail(
                "x@y.com",
                "INVOICE overdue notice",
                "Please URGENT payment today",
                null
        );

        RuleEvaluationResult res = service.evaluate(email);

        assertNull(res.getForcedVerdict(), "No verdict rule => forcedVerdict should be null");
        assertEquals(70, res.getTotalScore(), "40 + 30");
        assertEquals(2, res.getHits().size(), "Both rules should be traced");

        assertNotNull(res.getHits().get(0).getScoreDelta());
        assertNotNull(res.getHits().get(1).getScoreDelta());
    }

    @Test
    void attachmentExtensionRule_blocksOnExe() {
        RuleEntity extBlock = mockRule(
                UUID.randomUUID(),
                "Block dangerous ext",
                true,
                RuleTarget.ATTACHMENT_EXT,
                RuleAction.SET_VERDICT,
                "exe,js,iso",
                null,
                EmailVerdict.BLOCK
        );

        when(ruleRepository.findByEnabledTrueOrderByPriorityAsc()).thenReturn(List.of(extBlock));

        ParsedEmail email = baseEmail("a@b.com", "hi", "body", null);
        AttachmentMeta att = new AttachmentMeta();
        att.filename = "invoice.EXE";
        att.size = 123;
        email.attachments = List.of(att);

        RuleEvaluationResult res = service.evaluate(email);

        assertEquals(EmailVerdict.BLOCK, res.getForcedVerdict());
        assertEquals(1, res.getHits().size());
        assertEquals(EmailVerdict.BLOCK, res.getHits().get(0).getForcedVerdict());
        assertTrue(res.getHits().get(0).getMessage().toLowerCase().contains("extension")
                        || res.getHits().get(0).getMessage().toLowerCase().contains("exe"),
                "Message should explain extension match");
    }

    @Test
    void attachmentSizeRule_quarantinesWhenOverMax() {
        RuleEntity sizeRule = mockRule(
                UUID.randomUUID(),
                "Large attachment",
                true,
                RuleTarget.ATTACHMENT_SIZE,
                RuleAction.SET_VERDICT,
                "max:10",
                null,
                EmailVerdict.QUARANTINE
        );

        when(ruleRepository.findByEnabledTrueOrderByPriorityAsc()).thenReturn(List.of(sizeRule));

        ParsedEmail email = baseEmail("a@b.com", "hi", "body", null);
        AttachmentMeta att = new AttachmentMeta();
        att.filename = "big.pdf";
        att.size = 11;
        email.attachments = List.of(att);

        RuleEvaluationResult res = service.evaluate(email);

        assertEquals(EmailVerdict.QUARANTINE, res.getForcedVerdict());
        assertEquals(1, res.getHits().size());
        assertEquals(EmailVerdict.QUARANTINE, res.getHits().get(0).getForcedVerdict());
        assertTrue(res.getHits().get(0).getMessage().toLowerCase().contains("size"),
                "Message should mention size");
    }

    @Test
    void disabledRulesAreIgnored() {
        RuleEntity disabledBlock = mockRule(
                UUID.randomUUID(),
                "Disabled blacklist",
                false,
                RuleTarget.SENDER_DOMAIN,
                RuleAction.SET_VERDICT,
                "evil.com",
                null,
                EmailVerdict.BLOCK
        );

        when(ruleRepository.findByEnabledTrueOrderByPriorityAsc()).thenReturn(List.of(disabledBlock));

        ParsedEmail email = baseEmail("x@evil.com", "hi", "body", null);

        RuleEvaluationResult res = service.evaluate(email);

        assertNull(res.getForcedVerdict(), "Disabled rule should not apply");
        assertEquals(0, res.getTotalScore());
        assertTrue(res.getHits().isEmpty(), "No hits expected");
    }

    @Test
    void bypassForcesAllow_andStopsFurtherRules() {
        RuleEntity whitelistBypass = mockRule(
                UUID.randomUUID(),
                "Whitelist partner",
                true,
                RuleTarget.SENDER_EMAIL,
                RuleAction.BYPASS,
                "vip@company.com",
                null,
                null
        );

        RuleEntity scoreAfter = mockRule(
                UUID.randomUUID(),
                "Should not run after bypass",
                true,
                RuleTarget.SUBJECT,
                RuleAction.ADD_SCORE,
                ".*",
                999,
                null
        );

        when(ruleRepository.findByEnabledTrueOrderByPriorityAsc()).thenReturn(List.of(scoreAfter, whitelistBypass));

        ParsedEmail email = baseEmail("vip@company.com", "anything", "body", null);

        RuleEvaluationResult res = service.evaluate(email);

        assertEquals(EmailVerdict.ALLOW, res.getForcedVerdict(), "BYPASS must force ALLOW");
        assertEquals(0, res.getTotalScore(), "Should stop before adding score");
        assertTrue(res.getHits().size() >= 1);
    }
}