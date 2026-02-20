import { useEffect, useMemo, useState } from "react";
import { hasRole } from "../utils/auth";
import "./RulesPage.css";

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
const VERDICTS = ["ALLOW", "BLOCK"];

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

            {!canManage && (
                <div className="notice noticeWarn" style={{ marginTop: 16 }}>
                    <div className="noticeTitle">Acces restricționat</div>
                    <div className="noticeText">
                        Contul tău nu are permisiuni de administrare. Poți vedea lista de reguli, dar nu le poți modifica.
                    </div>
                </div>
            )}

            <div className="cardsGrid">
                {/* Lista */}
                <section className="card">
                    <div className="cardHead">
                        <div>
                            <div className="cardTitle">Lista reguli</div>
                            <p className="cardSubtitle">Ordinea efectivă este după priority (asc).</p>
                        </div>

                        <div className="cardActions">
                            <button className="btn btnGhost" onClick={loadRules} disabled={loading}>
                                Refresh
                            </button>
                            <button className="btn" onClick={startCreate} disabled={!canManage}>
                                + New Rule
                            </button>
                        </div>
                    </div>

                    {loading && <p className="muted">Se încarcă…</p>}
                    {err && (
                        <div className="box error">
                            <div className="boxTitle">Eroare</div>
                            <pre className="mono">{err}</pre>
                        </div>
                    )}

                    {!loading && !err && rules.length === 0 && (
                        <p className="muted">Nu există reguli încă. Creează una cu “New Rule”.</p>
                    )}

                    {!loading && !err && rules.length > 0 && (
                        <div className="rulesTableWrap">
                            <table className="table">
                                <thead>
                                <tr>
                                    <th>Enabled</th>
                                    <th>Name</th>
                                    <th>Target</th>
                                    <th>Action</th>
                                    <th>Pattern</th>
                                    <th>Priority</th>
                                    <th style={{ width: 140 }}>Actions</th>
                                </tr>
                                </thead>
                                <tbody>
                                {rules.map((r) => {
                                    const active = r.id === selectedId;
                                    return (
                                        <tr
                                            key={r.id}
                                            className={active ? "rowActive" : ""}
                                            onClick={() => startEdit(r)}
                                            style={{ cursor: "pointer" }}
                                            title="Click pentru edit"
                                        >
                                            <td onClick={(e) => e.stopPropagation()}>
                                                <label className="switch">
                                                    <input
                                                        type="checkbox"
                                                        checked={!!r.enabled}
                                                        onChange={(e) => toggleEnabled(r, e.target.checked)}
                                                        disabled={!canManage}
                                                    />
                                                    <span className="slider" />
                                                </label>
                                            </td>
                                            <td>
                                                <div className="cellMain">{r.name}</div>
                                                <div className="cellSub monoInline">{r.id}</div>
                                            </td>
                                            <td>
                                                <span className="pill">{r.target}</span>
                                            </td>
                                            <td>
                                                <span className="pill pill2">{r.action}</span>
                                                {r.action === "SET_VERDICT" && r.verdict && (
                                                    <span className={`badge ${r.verdict === "BLOCK" ? "badgeRed" : "badgeGreen"}`}>
                              {r.verdict}
                            </span>
                                                )}
                                                {r.action === "ADD_SCORE" && (
                                                    <span className="badge badgeBlue">
                              {Number(r.scoreDelta || 0) >= 0 ? "+" : ""}
                                                        {r.scoreDelta || 0}
                            </span>
                                                )}
                                            </td>
                                            <td className="monoInline">{r.pattern}</td>
                                            <td className="monoInline">{r.priority}</td>
                                            <td onClick={(e) => e.stopPropagation()}>
                                                <div className="rowBtns">
                                                    <button className="btn btnGhost" onClick={() => startEdit(r)}>
                                                        Edit
                                                    </button>
                                                    <button className="btn btnDanger" onClick={() => deleteRule(r)} disabled={!canManage}>
                                                        Delete
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </section>

                {/* Editor */}
                <section className="card">
                    <div className="cardTitle">{form.id ? "Edit Rule" : "Create Rule"}</div>

                    <div className="form">
                        <label>
                            Name
                            <input
                                value={form.name}
                                onChange={(e) => patchForm({ name: e.target.value })}
                                placeholder="ex: Block suspicious domain"
                                disabled={!canManage}
                            />
                        </label>

                        <div className="row">
                            <label>
                                Target
                                <select
                                    className="select"
                                    value={form.target}
                                    onChange={(e) => patchForm({ target: e.target.value })}
                                    disabled={!canManage}
                                >
                                    {TARGETS.map((t) => (
                                        <option key={t} value={t}>
                                            {t}
                                        </option>
                                    ))}
                                </select>
                            </label>

                            <label>
                                Action
                                <select
                                    className="select"
                                    value={form.action}
                                    onChange={(e) => patchForm({ action: e.target.value })}
                                    disabled={!canManage}
                                >
                                    {ACTIONS.map((a) => (
                                        <option key={a} value={a}>
                                            {a}
                                        </option>
                                    ))}
                                </select>
                            </label>
                        </div>

                        {(targetHint || actionHint) && (
                            <div className="notice" style={{ padding: 12 }}>
                                <div className="noticeText">
                                    <div style={{ fontWeight: 800, marginBottom: 4 }}>Hints</div>
                                    {targetHint && <div>• {targetHint}</div>}
                                    {actionHint && <div>• {actionHint}</div>}
                                </div>
                            </div>
                        )}

                        <label>
                            Pattern
                            <input
                                value={form.pattern}
                                onChange={(e) => patchForm({ pattern: e.target.value })}
                                placeholder={
                                    form.target === "SUBJECT" || form.target === "BODY"
                                        ? "kw:paypal  (sau regex)"
                                        : form.target === "ATTACHMENT_SIZE"
                                            ? "max:1048576"
                                            : ""
                                }
                                disabled={!canManage}
                            />
                            <div className="hint">{targetHint}</div>
                        </label>

                        {form.action === "ADD_SCORE" && (
                            <label>
                                Score Delta
                                <input
                                    type="number"
                                    value={form.scoreDelta}
                                    onChange={(e) => patchForm({ scoreDelta: e.target.value })}
                                    disabled={!canManage}
                                />
                                <div className="hint">Poate fi negativ (reduce scor).</div>
                            </label>
                        )}

                        {form.action === "SET_VERDICT" && (
                            <label>
                                Verdict
                                <select
                                    className="select"
                                    value={form.verdict}
                                    onChange={(e) => patchForm({ verdict: e.target.value })}
                                    disabled={!canManage}
                                >
                                    {VERDICTS.map((v) => (
                                        <option key={v} value={v}>
                                            {v}
                                        </option>
                                    ))}
                                </select>
                            </label>
                        )}

                        <div className="row">
                            <label>
                                Priority
                                <input
                                    type="number"
                                    value={form.priority}
                                    onChange={(e) => patchForm({ priority: e.target.value })}
                                    disabled={!canManage}
                                />
                                <div className="hint">Mai mic = rule mai devreme (ex: 1..999).</div>
                            </label>

                            <label>
                                Enabled
                                <select
                                    className="select"
                                    value={form.enabled ? "true" : "false"}
                                    onChange={(e) => patchForm({ enabled: e.target.value === "true" })}
                                    disabled={!canManage}
                                >
                                    <option value="true">true</option>
                                    <option value="false">false</option>
                                </select>
                            </label>
                        </div>

                        <div className="hintRow">
                            <button className="btn btnGhost" onClick={startCreate} disabled={!canManage}>
                                Reset
                            </button>
                            <button className="btn" onClick={saveRule} disabled={!canManage || saving}>
                                {saving ? "Saving…" : form.id ? "Save changes" : "Create rule"}
                            </button>
                        </div>

                        {saveOk && (
                            <div className="box result">
                                <div className="boxTitle">OK</div>
                                <pre className="mono">{saveOk}</pre>
                            </div>
                        )}

                        {saveErr && (
                            <div className="box error">
                                <div className="boxTitle">Eroare</div>
                                <pre className="mono">{saveErr}</pre>
                            </div>
                        )}

                        {selectedRule && (
                            <div className="box" style={{ border: "1px solid rgba(255,255,255,0.10)", background: "rgba(10,25,47,0.55)" }}>
                                <div className="boxTitle">Selected rule (server)</div>
                                <pre className="mono">{pretty(selectedRule)}</pre>
                            </div>
                        )}
                    </div>
                </section>
            </div>
        </div>
    );
}