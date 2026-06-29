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

function aiBadgeClass(score) {
    if (score === null || score === undefined) return "badge badgeNone";
    if (score >= 80) return "badge badgeFail";
    if (score >= 50) return "badge badgeWarn";
    return "badge badgePass";
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

    const [expandedSecurity, setExpandedSecurity] = useState(null);
    const [expandedSecurityLoading, setExpandedSecurityLoading] = useState(false);

    const hasData = useMemo(() => Array.isArray(emails) && emails.length > 0, [emails]);

    const [moving, setMoving] = useState(false);
    const [spamLoadingId, setSpamLoadingId] = useState(null);

    async function analyzeSpam(emailId) {
        setSpamLoadingId(emailId);

        try {
            const token = localStorage.getItem("token");

            const res = await fetch(`/api/emails/${emailId}/analyze-spam`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                },
            });

            if (!res.ok) {
                throw new Error("Spam analysis failed");
            }

            const data = await res.json();
            console.log(data);

            await loadEmails();

        } catch (err) {
            console.error(err);
            alert("Could not analyze spam");
        } finally {
            setSpamLoadingId(null);
        }
    }

    async function loadEmails() {
        setLoading(true);
        setError(null);

        try {
            const data = await fetchJson("/api/emails", { method: "GET" });
            setEmails(Array.isArray(data) ? data : []);
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        void loadEmails();
    }, []);

    async function moveSuspiciousEmails() {
        try {
            setMoving(true);

            const token = localStorage.getItem("token");
            const mailboxConfig = JSON.parse(localStorage.getItem("mailboxConfig") || "null");

            if (!mailboxConfig?.host || !mailboxConfig?.username || !mailboxConfig?.password) {
                throw new Error("Lipsește configurația IMAP. Rulează întâi Analyze Email din Ingestion.");
            }

            const res = await fetch("/api/mailbox/fetch", {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(mailboxConfig),
            });

            const text = await res.text();
            const data = text ? JSON.parse(text) : null;

            if (!res.ok) {
                throw new Error(data?.message || data?.error || `HTTP ${res.status}`);
            }

            alert("Suspicious emails moved successfully.");
            await loadEmails();
        } catch (e) {
            alert(e.message || "Move failed");
        } finally {
            setMoving(false);
        }
    }

    function statusBadgeClass(status) {
        if (status === "QUARANTINED") return "badge badgeFail";
        if (status === "ANALYZED") return "badge badgePass";
        if (status === "RECEIVED" || status === "PARSED") return "badge badgeWarn";
        if (status === "DELETED") return "badge badgeFail";
        if (status === "RELEASED") return "badge badgePass";
        return "badge badgeNone";
    }

    async function toggleExpand(emailId) {
        if (!emailId) return;

        if (expandedEmailId === emailId) {
            setExpandedEmailId(null);
            setExpandedAuth(null);
            setExpandedRuleHits(null);
            setExpandedSecurity(null);
            return;
        }

        setExpandedEmailId(emailId);

        setExpandedAuth(null);
        setExpandedRuleHits(null);
        setExpandedSecurity(null);

        setExpandedAuthLoading(true);
        setExpandedRuleHitsLoading(true);
        setExpandedSecurityLoading(true);

        try {
            const [auth, hits, security] = await Promise.all([
                fetchJson(`/api/emails/${emailId}/auth`, { method: "GET" }).catch((e) => ({
                    error: e?.message || String(e),
                })),
                fetchJson(`/api/emails/${emailId}/rule-hits`, { method: "GET" }).catch((e) => ({
                    error: e?.message || String(e),
                })),
                fetchJson(`/api/emails/${emailId}/security`, { method: "GET" }).catch((e) => ({
                    error: e?.message || String(e),
                })),
            ]);

            setExpandedAuth(auth);
            setExpandedRuleHits(hits);
            setExpandedSecurity(security);
        } finally {
            setExpandedAuthLoading(false);
            setExpandedRuleHitsLoading(false);
            setExpandedSecurityLoading(false);
        }
    }

    return (
        <div className="page">
            <div
                className="pageHeader">
                <h1>Emails Report</h1>

                <button
                    className="moveSuspiciousBtn"
                    onClick={moveSuspiciousEmails}
                    disabled={moving}
                >
                    {moving ? "Moving..." : "→ Move suspicious emails from inbox"}
                </button>
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
                                <th>Status</th>
                                <th>SPF</th>
                                <th>DKIM</th>
                                <th>DMARC</th>
                                <th>URLs</th>
                                <th>Attachments</th>
                                <th>AI</th>
                                <th>Classification</th>
                                <th>Actions</th>
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
                                            <td>
                                            <span className={statusBadgeClass(e.status)}>
                                                {safe(e.status)}
                                            </span>
                                            </td>
                                            <td>{safe(e.spfResult)}</td>
                                            <td>{safe(e.dkimResult)}</td>
                                            <td>{safe(e.dmarcResult)}</td>

                                            <td>
                                                {e.urlStatus === "SUSPICIOUS" ? (
                                                    <span className="badge badgeFail">
                                                            Suspicious ({e.suspiciousUrlCount ?? 0})
                                                        </span>
                                                ) : e.urlStatus === "CLEAN" ? (
                                                    <span className="badge badgePass">Clean</span>
                                                ) : (
                                                    <span className="badge badgeNone">None</span>
                                                )}
                                            </td>

                                            <td>
                                                {e.attachmentStatus === "SUSPICIOUS" ? (
                                                    <span className="badge badgeFail">
                                                            Suspicious ({e.suspiciousAttachmentCount ?? 0})
                                                        </span>
                                                ) : e.attachmentStatus === "CLEAN" ? (
                                                    <span className="badge badgePass">
                                                            Clean ({e.attachmentCount ?? 0})
                                                        </span>
                                                ) : (
                                                    <span className="badge badgeNone">None</span>
                                                )}
                                            </td>

                                            <td>
                                                    <span className={aiBadgeClass(e.aiSpamScore)}>
                                                        {e.aiSpamScore ?? "-"}
                                                    </span>
                                            </td>

                                            <td>{safe(e.aiClassification)}</td>

                                            <td onClick={(ev) => ev.stopPropagation()}>
                                                {e.aiSpamScore == null ? (
                                                    <button
                                                        className="spamBtn"
                                                        onClick={() => analyzeSpam(e.emailId)}
                                                    >
                                                        AI Scan
                                                    </button>
                                                ) : (
                                                    <button
                                                        className="spamBtn reanalyzeBtn"
                                                        onClick={() => analyzeSpam(e.emailId)}
                                                    >
                                                        Reanalyze
                                                    </button>
                                                )}
                                            </td>
                                        </tr>

                                        {isExpanded && (
                                            <tr key={`${e.emailId}-details`}>
                                                <td colSpan={14} style={{ padding: 0 }}>
                                                    <div
                                                        style={{
                                                            padding: 14,
                                                            display: "grid",
                                                            gap: 14,
                                                        }}
                                                    >
                                                        <div>
                                                            <div
                                                                className="cardTitle"
                                                                style={{ marginBottom: 10 }}
                                                            >
                                                                Identity checks
                                                            </div>

                                                            {expandedAuthLoading && (
                                                                <div className="notice">
                                                                    Loading auth details...
                                                                </div>
                                                            )}

                                                            {!expandedAuthLoading && expandedAuth?.error && (
                                                                <div className="box error">
                                                                    <div className="boxTitle">
                                                                        Auth details error
                                                                    </div>
                                                                    <pre className="mono">
                                                                            {String(expandedAuth.error)}
                                                                        </pre>
                                                                </div>
                                                            )}

                                                            {!expandedAuthLoading &&
                                                                expandedAuth &&
                                                                !expandedAuth?.error && (
                                                                    <AuthResultsCard
                                                                        data={expandedAuth}
                                                                        security={
                                                                            expandedSecurityLoading
                                                                                ? null
                                                                                : expandedSecurity
                                                                        }
                                                                    />
                                                                )}
                                                        </div>

                                                        <div>
                                                            <div
                                                                className="cardTitle"
                                                                style={{ marginBottom: 10 }}
                                                            >
                                                                Rule hits
                                                            </div>

                                                            {expandedRuleHitsLoading && (
                                                                <div className="notice">
                                                                    Loading rule hits...
                                                                </div>
                                                            )}

                                                            {!expandedRuleHitsLoading &&
                                                                expandedRuleHits?.error && (
                                                                    <div className="box error">
                                                                        <div className="boxTitle">
                                                                            Rule hits error
                                                                        </div>
                                                                        <pre className="mono">
                                                                                {String(expandedRuleHits.error)}
                                                                            </pre>
                                                                    </div>
                                                                )}

                                                            {!expandedRuleHitsLoading &&
                                                                Array.isArray(expandedRuleHits) &&
                                                                expandedRuleHits.length === 0 && (
                                                                    <div className="notice">
                                                                        No rule hits for this email.
                                                                    </div>
                                                                )}

                                                            {!expandedRuleHitsLoading &&
                                                                Array.isArray(expandedRuleHits) &&
                                                                expandedRuleHits.length > 0 && (
                                                                    <div
                                                                        className="box"
                                                                        style={{
                                                                            border:
                                                                                "1px solid rgba(255,255,255,0.10)",
                                                                            background:
                                                                                "rgba(10,25,47,0.40)",
                                                                        }}
                                                                    >
                                                                        <div
                                                                            style={{
                                                                                display: "grid",
                                                                                gap: 10,
                                                                            }}
                                                                        >
                                                                            {expandedRuleHits.map((h, idx) => (
                                                                                <div
                                                                                    key={idx}
                                                                                    style={{
                                                                                        display: "grid",
                                                                                        gap: 4,
                                                                                        paddingBottom: 10,
                                                                                        borderBottom:
                                                                                            idx ===
                                                                                            expandedRuleHits.length -
                                                                                            1
                                                                                                ? "none"
                                                                                                : "1px solid rgba(255,255,255,0.08)",
                                                                                    }}
                                                                                >
                                                                                    <div
                                                                                        style={{
                                                                                            display: "flex",
                                                                                            gap: 10,
                                                                                            alignItems: "baseline",
                                                                                            flexWrap: "wrap",
                                                                                        }}
                                                                                    >
                                                                                            <span
                                                                                                style={{
                                                                                                    fontWeight: 800,
                                                                                                }}
                                                                                            >
                                                                                                {h.ruleName || "(rule)"}
                                                                                            </span>

                                                                                        {h.scoreDelta !== null &&
                                                                                            h.scoreDelta !==
                                                                                            undefined && (
                                                                                                <span className="badge badgeWarn">
                                                                                                        score{" "}
                                                                                                    {h.scoreDelta > 0
                                                                                                        ? `+${h.scoreDelta}`
                                                                                                        : String(
                                                                                                            h.scoreDelta
                                                                                                        )}
                                                                                                    </span>
                                                                                            )}

                                                                                        {h.forcedVerdict && (
                                                                                            <span className="badge badgeFail">
                                                                                                    verdict{" "}
                                                                                                {String(
                                                                                                    h.forcedVerdict
                                                                                                )}
                                                                                                </span>
                                                                                        )}

                                                                                        {h.timestamp && (
                                                                                            <span className="muted">
                                                                                                    {new Date(
                                                                                                        h.timestamp
                                                                                                    ).toLocaleString()}
                                                                                                </span>
                                                                                        )}
                                                                                    </div>

                                                                                    {h.message && (
                                                                                        <div className="muted">
                                                                                            {h.message}
                                                                                        </div>
                                                                                    )}
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
                    No emails available yet. Try analyzing emails first from the Ingestion page.
                </div>
            )}
        </div>
    );
}