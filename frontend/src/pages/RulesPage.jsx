import { useEffect, useMemo, useState } from "react";
import { hasRole } from "../utils/auth";
import "./RulesPage.css";
import RulesListCard from "../components/rules/RulesListCard.jsx";
import RuleEditorCard from "../components/rules/RulesEditorCard.jsx";

function pretty(obj) {
    try {
        return JSON.stringify(obj, null, 2);
    } catch {
        return String(obj);
    }
}

const TARGETS = [
    "SENDER_EMAIL",
    "SENDER_DOMAIN",
    "SUBJECT",
    "BODY",
    "ATTACHMENT_EXT",
    "ATTACHMENT_SIZE",
];

const ACTIONS = ["ADD_SCORE", "SET_VERDICT", "BYPASS"];
const VERDICTS = ["ALLOW", "BLOCK", "QUARANTINE"];

const emptyRule = {
    id: null,
    name: "",
    target: "SUBJECT",
    action: "ADD_SCORE",
    pattern: "",
    scoreDelta: 10,
    verdict: "BLOCK",
    priority: 100,
    enabled: true,
};

export default function RulesPage() {
    const canManage = hasRole("ADMIN");

    const [rules, setRules] = useState([]);
    const [loading, setLoading] = useState(false);
    const [err, setErr] = useState(null);

    const [selectedId, setSelectedId] = useState(null);
    const selectedRule = useMemo(
        () => rules.find((r) => r.id === selectedId) || null,
        [rules, selectedId]
    );

    const [form, setForm] = useState({ ...emptyRule });
    const [saving, setSaving] = useState(false);
    const [saveErr, setSaveErr] = useState(null);
    const [saveOk, setSaveOk] = useState(null);

    async function fetchJson(url, options = {}) {
        const token = localStorage.getItem("token");
        const headers = new Headers(options.headers || {});
        if (token) headers.set("Authorization", `Bearer ${token}`);
        if (!headers.has("Content-Type") && options.body && !(options.body instanceof FormData)) {
            headers.set("Content-Type", "application/json");
        }

        const res = await fetch(url, { ...options, headers });
        const text = await res.text();
        let data = null;
        try {
            data = text ? JSON.parse(text) : null;
        } catch {
            data = text || null;
        }

        if (!res.ok) {
            const msg =
                (data && data.message) ||
                (data && data.error) ||
                (typeof data === "string" ? data : null) ||
                `HTTP ${res.status}`;
            const e = new Error(msg);
            e.status = res.status;
            e.data = data;
            throw e;
        }
        return data;
    }

    async function loadRules() {
        setLoading(true);
        setErr(null);
        try {
            const data = await fetchJson("/api/rules");
            setRules(Array.isArray(data) ? data : []);
            if (selectedId && !data?.some?.((r) => r.id === selectedId)) setSelectedId(null);
        } catch (e) {
            setErr(e.message || String(e));
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        loadRules();
    }, []);

    function startCreate() {
        setSelectedId(null);
        setForm({ ...emptyRule });
        setSaveErr(null);
        setSaveOk(null);
    }

    function startEdit(rule) {
        setSelectedId(rule.id);
        setForm({
            id: rule.id,
            name: rule.name ?? "",
            target: rule.target ?? "SUBJECT",
            action: rule.action ?? "ADD_SCORE",
            pattern: rule.pattern ?? "",
            scoreDelta: rule.scoreDelta ?? 0,
            verdict: rule.verdict ?? "BLOCK",
            priority: rule.priority ?? 100,
            enabled: rule.enabled ?? true,
        });
        setSaveErr(null);
        setSaveOk(null);
    }

    function patchForm(p) {
        setForm((prev) => ({ ...prev, ...p }));
    }

    function normalizeBeforeSend(f) {
        const payload = {
            name: (f.name ?? "").trim(),
            target: f.target,
            action: f.action,
            pattern: f.pattern ?? "",
            priority: Number.isFinite(+f.priority) ? +f.priority : 100,
            enabled: !!f.enabled,
            scoreDelta: null,
            verdict: null,
        };

        if (payload.action === "ADD_SCORE") {
            payload.scoreDelta = Number.isFinite(+f.scoreDelta) ? +f.scoreDelta : 0;
        }
        if (payload.action === "SET_VERDICT") {
            payload.verdict = f.verdict || "BLOCK";
        }
        return payload;
    }

    async function saveRule() {
        setSaving(true);
        setSaveErr(null);
        setSaveOk(null);

        try {
            if (!canManage) throw new Error("Nu ai permisiuni pentru a modifica reguli.");

            const payload = normalizeBeforeSend(form);

            const isUpdate = !!form.id;
            const url = isUpdate ? `/api/rules/${form.id}` : "/api/rules";
            const method = isUpdate ? "PUT" : "POST";

            const saved = await fetchJson(url, {
                method,
                body: JSON.stringify(payload),
            });

            setSaveOk(isUpdate ? "Regula a fost actualizată." : "Regula a fost creată.");
            await loadRules();

            if (saved?.id) {
                setSelectedId(saved.id);
            }
        } catch (e) {
            setSaveErr(e.message || String(e));
        } finally {
            setSaving(false);
        }
    }

    async function deleteRule(rule) {
        if (!canManage) return;

        const ok = confirm(`Ștergi regula "${rule?.name || "Unnamed"}"?`);
        if (!ok) return;

        setSaveErr(null);
        setSaveOk(null);

        try {
            await fetchJson(`/api/rules/${rule.id}`, { method: "DELETE" });
            setSaveOk("Regula a fost ștearsă.");
            if (selectedId === rule.id) {
                setSelectedId(null);
                setForm({ ...emptyRule });
            }
            await loadRules();
        } catch (e) {
            setSaveErr(e.message || String(e));
        }
    }

    async function toggleEnabled(rule, value) {
        if (!canManage) return;

        setSaveErr(null);
        setSaveOk(null);

        try {
            const updated = await fetchJson(`/api/rules/${rule.id}/enabled?value=${value}`, {
                method: "PATCH",
            });

            setRules((prev) => prev.map((r) => (r.id === rule.id ? updated : r)));
            if (selectedId === rule.id) {
                setForm((prev) => ({ ...prev, enabled: updated.enabled }));
            }
        } catch (e) {
            setSaveErr(e.message || String(e));
        }
    }

    const actionHint = useMemo(() => {
        if (form.action === "ADD_SCORE") return "Scorul se adună la evaluare.";
        if (form.action === "SET_VERDICT") return "Forțează verdictul (ALLOW/BLOCK).";
        if (form.action === "BYPASS") return "Whitelist: forțează ALLOW indiferent de rest.";
        return "";
    }, [form.action]);

    const targetHint = useMemo(() => {
        if (form.target === "ATTACHMENT_EXT") return "Pattern: listă extensii separate prin virgulă (ex: pdf,exe,js)";
        if (form.target === "ATTACHMENT_SIZE") return "Pattern: max:<bytes> (ex: max:1048576 pentru 1MB)";
        if (form.target === "SUBJECT" || form.target === "BODY") return "Poți folosi: kw:oferta (substring) sau regex.";
        if (form.target === "SENDER_EMAIL") return "Match exact email (case-insensitive).";
        if (form.target === "SENDER_DOMAIN") return "Match domeniu sau subdomeniu (ex: example.com).";
        return "";
    }, [form.target]);

    return (
        <div className="page">
            <div className="pageHeader">
                <h1>Rules</h1>
                <p>Gestionează regulile (whitelist / blacklist / scoring) pentru evaluarea emailurilor.</p>
            </div>

            {canManage ? (
                <div className="cardsGrid">
                    <RulesListCard
                        canManage={canManage}
                        rules={rules}
                        selectedId={selectedId}
                        loading={loading}
                        err={err}
                        onRefresh={loadRules}
                        onNew={startCreate}
                        onEdit={startEdit}
                        onDelete={deleteRule}
                        onToggleEnabled={toggleEnabled}
                    />

                    <RuleEditorCard
                        canManage={canManage}
                        form={form}
                        TARGETS={TARGETS}
                        ACTIONS={ACTIONS}
                        VERDICTS={VERDICTS}
                        targetHint={targetHint}
                        actionHint={actionHint}
                        saving={saving}
                        saveOk={saveOk}
                        saveErr={saveErr}
                        selectedRule={selectedRule}
                        pretty={pretty}
                        patchForm={patchForm}
                        startCreate={startCreate}
                        saveRule={saveRule}
                    />
                </div>
            ) : (
                <div className="cardsGrid single">
                    <RulesListCard
                        canManage={false}
                        rules={rules}
                        selectedId={selectedId}
                        loading={loading}
                        err={err}
                        onRefresh={loadRules}
                        onNew={() => {}}
                        onEdit={() => {}}
                        onDelete={() => {}}
                        onToggleEnabled={() => {}}
                    />
                </div>
            )}
        </div>
    );
}