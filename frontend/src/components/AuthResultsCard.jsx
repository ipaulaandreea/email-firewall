import { useMemo } from "react";

function normalizeResult(r) {
    if (!r) return "NONE";
    return String(r).toUpperCase();
}

function badgeClass(result) {
    switch (result) {
        case "PASS":
            return "badge badgePass";
        case "FAIL":
            return "badge badgeFail";
        case "SOFTFAIL":
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

export default function AuthResultsCard({ data }) {
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
                                        {(s?.domain || "-")}
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
                        <span className="muted">policy:</span> {String(data.dmarcPolicy || dmarc?.policy || "-")}
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

            <div className="muted" style={{ marginTop: 10 }}>
                Note: results are stored per email and contribute to the threat score.
            </div>
        </section>
    );
}

