export default function RuleEditorCard({
                                           canManage,
                                           form,
                                           TARGETS,
                                           ACTIONS,
                                           VERDICTS,
                                           targetHint,
                                           actionHint,
                                           saving,
                                           saveOk,
                                           saveErr,
                                           selectedRule,
                                           pretty,
                                           patchForm,
                                           startCreate,
                                           saveRule,
                                       }) {
    return (
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
                    <div
                        className="box"
                        style={{
                            border: "1px solid rgba(255,255,255,0.10)",
                            background: "rgba(10,25,47,0.55)",
                        }}
                    >
                        <div className="boxTitle">Selected rule (server)</div>
                        <pre className="mono">{pretty(selectedRule)}</pre>
                    </div>
                )}
            </div>
        </section>
    );
}