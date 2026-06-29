import { useMemo } from "react";

function normalizeResult(r) {
    if (!r) return "NONE";
    return String(r).toUpperCase();
}

function badgeClass(result) {
    switch (result) {
        case "PASS":
        case "CLEAN":
            return "badge badgePass";
        case "FAIL":
        case "SUSPICIOUS":
            return "badge badgeFail";
        case "SOFTFAIL":
        case "WARNING":
            return "badge badgeWarn";
        case "NEUTRAL":
        case "NONE":
        default:
            return "badge badgeNone";
    }
}

function Row({ label, result, children }) {
    const r = normalizeResult(result);
    return (
        <div className="authRow">
            <div className="authRowLeft">
                <div className="authLabel">{label}</div>
                <div className={badgeClass(r)}>{r}</div>
            </div>
            <div className="authRowBody">{children}</div>
        </div>
    );
}

function SecurityAnalysis({ security }) {
    if (!security) return null;

    const urls = Array.isArray(security.urls) ? security.urls : [];
    const attachments = Array.isArray(security.attachments) ? security.attachments : [];

    return (
        <>
            <div className="cardTitle" style={{ marginTop: 20 }}>
                URL & Attachment Analysis
            </div>

            <Row label="URLs" result={security.urlStatus || "NONE"}>
                <div className="authMeta">
                    <div>
                        <span className="muted">suspicious:</span>{" "}
                        {security.suspiciousUrlCount ?? 0}
                    </div>

                    {urls.length > 0 ? (
                        <div className="authList">
                            {urls.map((u, idx) => (
                                <div key={idx} className="authSig">
                                    <span className={badgeClass(normalizeResult(u.verdict))}>
                                        {normalizeResult(u.verdict)}
                                    </span>
                                    <span className="authSigText urlText">
                                        {u.host || "-"}
                                        {u.shortener ? " — shortener" : ""}
                                        {u.url ? ` — ${u.url}` : ""}
                                    </span>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="muted">No URLs detected.</div>
                    )}
                </div>
            </Row>

            <Row label="Attachments" result={security.attachmentStatus || "NONE"}>
                <div className="authMeta">
                    <div>
                        <span className="muted">total:</span>{" "}
                        {security.attachmentCount ?? 0}
                        {" · "}
                        <span className="muted">suspicious:</span>{" "}
                        {security.suspiciousAttachmentCount ?? 0}
                    </div>

                    {attachments.length > 0 ? (
                        <div className="authList">
                            {attachments.map((a, idx) => (
                                <div key={idx} className="authSig">
                                    <span className={badgeClass(normalizeResult(a.verdict))}>
                                        {normalizeResult(a.verdict)}
                                    </span>
                                    <span className="authSigText">
                                        {a.filename || "-"}
                                        {a.extension ? ` (.${a.extension})` : ""}
                                        {a.sizeBytes ? ` — ${a.sizeBytes} bytes` : ""}
                                    </span>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="muted">No attachments detected.</div>
                    )}
                </div>
            </Row>
        </>
    );
}

export default function AuthResultsCard({ data, security }) {
    const details = useMemo(() => {
        if (!data) return null;
        return data.details || null;
    }, [data]);

    if (!data) return null;

    const spf = details?.spf;
    const dkim = details?.dkim;
    const dmarc = details?.dmarc;

    return (
        <section className="card">
            <div className="cardTitle">Identity checks (SPF / DKIM / DMARC)</div>

            <Row label="SPF" result={data.spfResult || spf?.result}>
                <div className="authMeta">
                    {(spf?.domain || null) && (
                        <div>
                            <span className="muted">domain:</span> {spf.domain}
                        </div>
                    )}
                    {(spf?.summary || null) && <div className="muted">{spf.summary}</div>}
                </div>
            </Row>

            <Row label="DKIM" result={data.dkimResult || dkim?.result}>
                <div className="authMeta">
                    {(dkim?.summary || null) && <div className="muted">{dkim.summary}</div>}
                    {Array.isArray(dkim?.signatures) && dkim.signatures.length > 0 && (
                        <div className="authList">
                            <div className="muted" style={{ marginBottom: 6 }}>
                                signatures:
                            </div>
                            {dkim.signatures.map((s, idx) => (
                                <div key={idx} className="authSig">
                                    <span className={badgeClass(normalizeResult(s?.result))}>
                                        {normalizeResult(s?.result)}
                                    </span>
                                    <span className="authSigText">
                                        {s?.domain || "-"}
                                        {s?.selector ? ` (selector=${s.selector})` : ""}
                                        {s?.summary ? ` — ${s.summary}` : ""}
                                    </span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </Row>

            <Row label="DMARC" result={data.dmarcResult || dmarc?.result}>
                <div className="authMeta">
                    <div>
                        <span className="muted">policy:</span>{" "}
                        {String(data.dmarcPolicy || dmarc?.policy || "-")}
                    </div>
                    {(dmarc?.spfAligned !== undefined || dmarc?.dkimAligned !== undefined) && (
                        <div>
                            <span className="muted">alignment:</span>{" "}
                            SPF={String(dmarc?.spfAligned ?? "-")}, DKIM={String(dmarc?.dkimAligned ?? "-")}
                        </div>
                    )}
                    {(dmarc?.summary || null) && <div className="muted">{dmarc.summary}</div>}
                </div>
            </Row>

            <SecurityAnalysis security={security} />

            <div className="muted" style={{ marginTop: 10 }}>
                Note: results are stored per email and contribute to the threat score.
            </div>
        </section>
    );
}