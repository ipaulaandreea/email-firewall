export default function RulesListCard({
                                          canManage,
                                          rules,
                                          selectedId,
                                          loading,
                                          err,
                                          onRefresh,
                                          onNew,
                                          onEdit,
                                          onDelete,
                                          onToggleEnabled,
                                      }) {
    return (
        <section className="card">
            <div className="cardHead">
                <div>
                    <div className="cardTitle">Lista reguli</div>
                    <p className="cardSubtitle">Ordinea efectivă este după priority (asc).</p>
                </div>

                <div className="cardActions">
                    <button className="btn btnGhost" onClick={onRefresh} disabled={loading}>
                        Refresh
                    </button>

                    {canManage && (
                        <button className="btn" onClick={onNew}>
                            + New Rule
                        </button>
                    )}
                </div>
            </div>

            {loading && <p className="muted">Se încarcă…</p>}

            {err && (
                <div className="box error">
                    <div className="boxTitle">Eroare</div>
                    <pre className="mono">{err}</pre>
                </div>
            )}

            {!loading && !err && rules.length === 0 && <p className="muted">Nu există reguli.</p>}

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
                            {canManage && <th style={{ width: 140 }}>Actions</th>}
                        </tr>
                        </thead>

                        <tbody>
                        {rules.map((r) => {
                            const active = r.id === selectedId;

                            return (
                                <tr
                                    key={r.id}
                                    className={active ? "rowActive" : ""}
                                    onClick={canManage ? () => onEdit(r) : undefined}
                                    style={{ cursor: canManage ? "pointer" : "default" }}
                                    title={canManage ? "Click pentru edit" : undefined}
                                >
                                    <td onClick={(e) => e.stopPropagation()}>
                                        {canManage ? (
                                            <label className="switch">
                                                <input
                                                    type="checkbox"
                                                    checked={!!r.enabled}
                                                    onChange={(e) => onToggleEnabled(r, e.target.checked)}
                                                />
                                                <span className="slider" />
                                            </label>
                                        ) : (
                                            <span className={`badge ${r.enabled ? "badgeGreen" : "badgeRed"}`}>
                          {r.enabled ? "ON" : "OFF"}
                        </span>
                                        )}
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

                                    {canManage && (
                                        <td onClick={(e) => e.stopPropagation()}>
                                            <div className="rowBtns">
                                                <button className="btn btnGhost" onClick={() => onEdit(r)}>
                                                    Edit
                                                </button>
                                                <button className="btn btnDanger" onClick={() => onDelete(r)}>
                                                    Delete
                                                </button>
                                            </div>
                                        </td>
                                    )}
                                </tr>
                            );
                        })}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}