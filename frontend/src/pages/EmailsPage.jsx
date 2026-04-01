import { useEffect, useMemo, useState } from "react";
import AuthResultsCard from "../components/AuthResultsCard";

function safe(v) {
    return v === null || v === undefined || v === "" ? "-" : String(v);
}

function formatDate(iso) {
    if (!iso) return "-";
    try {
        return new Date(iso).toLocaleString();
    } catch {
        return String(iso);
    }
}

async function fetchJson(url, options = {}) {
    const token = localStorage.getItem("token");

    const headers = new Headers(options.headers || {});
    if (token) headers.set("Authorization", `Bearer ${token}`);

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
        const err = new Error(msg);
        err.status = res.status;
        err.data = data;
        throw err;
    }

    return data;
}

export default function EmailsPage() {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [emails, setEmails] = useState([]);

    const [expandedEmailId, setExpandedEmailId] = useState(null);
    const [expandedAuth, setExpandedAuth] = useState(null);
    const [expandedAuthLoading, setExpandedAuthLoading] = useState(false);

    const [expandedRuleHits, setExpandedRuleHits] = useState(null);
    const [expandedRuleHitsLoading, setExpandedRuleHitsLoading] = useState(false);

    const hasData = useMemo(() => Array.isArray(emails) && emails.length > 0, [emails]);

    useEffect(() => {
        let cancelled = false;

        async function load() {
            setLoading(true);
            setError(null);
            try {
                const data = await fetchJson("/api/emails", { method: "GET" });
                if (!cancelled) setEmails(Array.isArray(data) ? data : []);
            } catch (e) {
                if (!cancelled) setError(e);
            } finally {
                if (!cancelled) setLoading(false);
            }
        }

        void load();
        return () => {
            cancelled = true;
        };
    }, []);

    async function toggleExpand(emailId) {
        if (!emailId) return;

        if (expandedEmailId === emailId) {
            setExpandedEmailId(null);
            setExpandedAuth(null);
            setExpandedRuleHits(null);
            return;
        }

        setExpandedEmailId(emailId);

        setExpandedAuth(null);
        setExpandedAuthLoading(true);

        setExpandedRuleHits(null);
        setExpandedRuleHitsLoading(true);

        try {
            const [auth, hits] = await Promise.all([
                fetchJson(`/api/emails/${emailId}/auth`, { method: "GET" }).catch((e) => ({ error: e?.message || String(e) })),
                fetchJson(`/api/emails/${emailId}/rule-hits`, { method: "GET" }).catch((e) => ({ error: e?.message || String(e) })),
            ]);

            setExpandedAuth(auth);
            setExpandedRuleHits(hits);
        } finally {
            setExpandedAuthLoading(false);
            setExpandedRuleHitsLoading(false);
        }
    }

    return (
        <div className="page">
            <div className="pageHeader">
                <h1>Emails</h1>
                <p>Ultimele 50 emailuri ingerate + rezumat SPF/DKIM/DMARC. Click pe un rând pentru detalii.</p>
            </div>

            {loading && <div className="notice">Loading...</div>}
            {error && (
                <div className="box error">
                    <div className="boxTitle">Error</div>
                    <pre className="mono">{String(error?.message || error)}</pre>
                </div>
            )}

            {hasData && (
                <div className="card span2">
                    <div className="emailsTableWrap">
                        <table className="emailsTable">
                            <thead>
                                <tr>
                                    <th>Received</th>
                                    <th>From</th>
                                    <th>Subject</th>
                                    <th>Score</th>
                                    <th>Verdict</th>
                                    <th>SPF</th>
                                    <th>DKIM</th>
                                    <th>DMARC</th>
                                    <th>Policy</th>
                                </tr>
                            </thead>
                            <tbody>
                                {emails.map((e) => {
                                    const isExpanded = expandedEmailId === e.emailId;
                                    return (
                                        <>
                                            <tr
                                                key={e.emailId}
                                                className={isExpanded ? "rowExpanded" : ""}
                                                onClick={() => toggleExpand(e.emailId)}
                                                style={{ cursor: "pointer" }}
                                                title="Click pentru detalii"
                                            >
                                                <td>{formatDate(e.receivedAt)}</td>
                                                <td className="cellMono">{safe(e.fromAddress)}</td>
                                                <td>{safe(e.subject)}</td>
                                                <td className="cellMono">{safe(e.threatScore)}</td>
                                                <td>{safe(e.verdict)}</td>
                                                <td>{safe(e.spfResult)}</td>
                                                <td>{safe(e.dkimResult)}</td>
                                                <td>{safe(e.dmarcResult)}</td>
                                                <td>{safe(e.dmarcPolicy)}</td>
                                            </tr>

                                            {isExpanded && (
                                                <tr key={`${e.emailId}-details`}>
                                                    <td colSpan={9} style={{ padding: 0 }}>
                                                        <div style={{ padding: 14, display: "grid", gap: 14 }}>
                                                            <div>
                                                                <div className="cardTitle" style={{ marginBottom: 10 }}>
                                                                    Identity checks
                                                                </div>
                                                                {expandedAuthLoading && <div className="notice">Loading auth details...</div>}
                                                                {!expandedAuthLoading && expandedAuth?.error && (
                                                                    <div className="box error">
                                                                        <div className="boxTitle">Auth details error</div>
                                                                        <pre className="mono">{String(expandedAuth.error)}</pre>
                                                                    </div>
                                                                )}
                                                                {!expandedAuthLoading && expandedAuth && !expandedAuth?.error && (
                                                                    <AuthResultsCard data={expandedAuth} />
                                                                )}
                                                            </div>

                                                            <div>
                                                                <div className="cardTitle" style={{ marginBottom: 10 }}>
                                                                    Rule hits
                                                                </div>

                                                                {expandedRuleHitsLoading && <div className="notice">Loading rule hits...</div>}

                                                                {!expandedRuleHitsLoading && expandedRuleHits?.error && (
                                                                    <div className="box error">
                                                                        <div className="boxTitle">Rule hits error</div>
                                                                        <pre className="mono">{String(expandedRuleHits.error)}</pre>
                                                                    </div>
                                                                )}

                                                                {!expandedRuleHitsLoading && Array.isArray(expandedRuleHits) && expandedRuleHits.length === 0 && (
                                                                    <div className="notice">No rule hits for this email.</div>
                                                                )}

                                                                {!expandedRuleHitsLoading && Array.isArray(expandedRuleHits) && expandedRuleHits.length > 0 && (
                                                                    <div className="box" style={{ border: "1px solid rgba(255,255,255,0.10)", background: "rgba(10,25,47,0.40)" }}>
                                                                        <div style={{ display: "grid", gap: 10 }}>
                                                                            {expandedRuleHits.map((h, idx) => (
                                                                                <div key={idx} style={{ display: "grid", gap: 4, paddingBottom: 10, borderBottom: idx === expandedRuleHits.length - 1 ? "none" : "1px solid rgba(255,255,255,0.08)" }}>
                                                                                    <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
                                                                                        <span style={{ fontWeight: 800 }}>{h.ruleName || "(rule)"}</span>
                                                                                        {h.scoreDelta !== null && h.scoreDelta !== undefined && (
                                                                                            <span className="badge badgeWarn">score {h.scoreDelta > 0 ? `+${h.scoreDelta}` : String(h.scoreDelta)}</span>
                                                                                        )}
                                                                                        {h.forcedVerdict && (
                                                                                            <span className="badge badgeFail">verdict {String(h.forcedVerdict)}</span>
                                                                                        )}
                                                                                        {h.timestamp && (
                                                                                            <span className="muted">{new Date(h.timestamp).toLocaleString()}</span>
                                                                                        )}
                                                                                    </div>
                                                                                    {h.message && <div className="muted">{h.message}</div>}
                                                                                </div>
                                                                            ))}
                                                                        </div>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                        </>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {!loading && !error && !hasData && (
                <div className="notice">
                    Nu există emailuri încă. Încearcă mai întâi un ingest din pagina Ingestion.
                </div>
            )}
        </div>
    );
}

