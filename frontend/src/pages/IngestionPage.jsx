import { useState } from "react";
import {hasRole} from "../utils/auth.js";

function pretty(obj) {
    try {
        return JSON.stringify(obj, null, 2);
    } catch {
        return String(obj);
    }
}

export default function IngestionPage() {
    const [mailboxForm, setMailboxForm] = useState({
        host: "imap.gmail.com",
        username: "",
        password: "",
        limit: "",
    });
    const canBatch = hasRole("ADMIN");

    const [mailboxLoading, setMailboxLoading] = useState(false);
    const [mailboxError, setMailboxError] = useState(null);
    const [mailboxResult, setMailboxResult] = useState(null);

    const [batchFiles, setBatchFiles] = useState([]);
    const [batchLoading, setBatchLoading] = useState(false);
    const [batchError, setBatchError] = useState(null);
    const [batchResult, setBatchResult] = useState(null);

    async function fetchJson(url, options = {}) {
        const token = localStorage.getItem("token");

        const headers = new Headers(options.headers || {});
        if (token) headers.set("Authorization", `Bearer ${token}`);
        if (options.body && !headers.has("Content-Type") && !(options.body instanceof FormData)) {
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
            const err = new Error(
                data?.message ||
                data?.error ||
                (typeof data === "string" ? data : null) ||
                `HTTP ${res.status}`
            );
            err.status = res.status;
            err.data = data;
            throw err;
        }

        return data;
    }

    async function submitMailboxAnalyze(e) {
        e.preventDefault();

        setMailboxLoading(true);
        setMailboxError(null);
        setMailboxResult(null);

        try {
            const data = await fetchJson("/api/mailbox/analyze", {
                method: "POST",
                body: JSON.stringify({
                    host: mailboxForm.host,
                    username: mailboxForm.username,
                    password: mailboxForm.password,
                    limit: mailboxForm.limit ? Number(mailboxForm.limit) : null,
                }),
            });

            localStorage.setItem(
                "mailboxConfig",
                JSON.stringify({
                    host: mailboxForm.host,
                    username: mailboxForm.username,
                    password: mailboxForm.password,
                    limit: mailboxForm.limit ? Number(mailboxForm.limit) : null,
                })
            );
            setMailboxResult(data);
        } catch (err) {
            setMailboxError(err);
        } finally {
            setMailboxLoading(false);
        }
    }

    async function submitBatch(e) {
        e.preventDefault();

        if (!batchFiles?.length) {
            setBatchError({ message: "Selectează cel puțin un fișier .eml" });
            return;
        }

        setBatchLoading(true);
        setBatchError(null);
        setBatchResult(null);

        try {
            const fd = new FormData();
            batchFiles.forEach((f) => fd.append("files", f));

            const data = await fetchJson("/api/ingest/eml/batch", {
                method: "POST",
                body: fd,
            });

            setBatchResult(data);
        } catch (err) {
            setBatchError(err);
        } finally {
            setBatchLoading(false);
        }
    }

    return (
        <div className="page">
            <div className="pageHeader">
                <h1>Analyze Emails</h1>
            </div>

            <div className="cardsGrid">
                <section className="card">
                    <div className="cardTitle">Analyze Email Address</div>

                    <form onSubmit={submitMailboxAnalyze} className="form">
                        <label>
                            IMAP Host
                            <input
                                value={mailboxForm.host}
                                onChange={(e) =>
                                    setMailboxForm((s) => ({ ...s, host: e.target.value }))
                                }
                                placeholder="imap.gmail.com"
                            />
                        </label>

                        <label>
                            Email address
                            <input
                                type="email"
                                value={mailboxForm.username}
                                onChange={(e) =>
                                    setMailboxForm((s) => ({ ...s, username: e.target.value }))
                                }
                                placeholder="your.email@gmail.com"
                            />
                        </label>

                        <label>
                            Password / App password
                            <input
                                type="password"
                                value={mailboxForm.password}
                                onChange={(e) =>
                                    setMailboxForm((s) => ({ ...s, password: e.target.value }))
                                }
                                placeholder="••••••••••••"
                            />
                        </label>

                        <label>
                            Limit (optional, default 10)
                            <input
                                type="number"
                                min="1"
                                max="200"
                                value={mailboxForm.limit}
                                placeholder="10"
                                onChange={(e) =>
                                    setMailboxForm((s) => ({ ...s, limit: e.target.value }))
                                }
                            />
                        </label>

                        <button className="btn" disabled={mailboxLoading}>
                            {mailboxLoading ? "Analyzing..." : "Analyze"}
                        </button>
                    </form>

                    {mailboxError && <ErrorBox err={mailboxError} />}
                    {mailboxResult && <ResultBox title="Analyze response" data={mailboxResult} />}
                </section>

                {canBatch && (
                    <section className="card">
                        <div className="cardTitle">Batch Ingest .eml Files </div>

                        <form onSubmit={submitBatch} className="form">
                            <label>
                                <input
                                    type="file"
                                    multiple
                                    accept=".eml,message/rfc822"
                                    onChange={(e) =>
                                        setBatchFiles(Array.from(e.target.files || []))
                                    }
                                />
                            </label>

                            <div className="hint">
                                Selected: <b>{batchFiles.length}</b>
                            </div>

                            <button
                                className="btn"
                                disabled={batchLoading || batchFiles.length === 0}
                            >
                                {batchLoading ? "Uploading..." : "Upload batch"}
                            </button>
                        </form>

                        {batchError && <ErrorBox err={batchError} />}
                        {batchResult && <ResultBox title="Batch response" data={batchResult} />}
                    </section>
                )}
            </div>
        </div>
    );
}

function ErrorBox({ err }) {
    return (
        <div className="box error">
            <div className="boxTitle">Error</div>
            <pre className="mono">{String(err?.message || err)}</pre>
            {err?.data ? (
                <>
                    <div className="boxTitle">Details</div>
                    <pre className="mono">{pretty(err.data)}</pre>
                </>
            ) : null}
        </div>
    );
}

function ResultBox({ title, data }) {
    return (
        <div className="box result">
            <div className="boxTitle">{title}</div>
            <pre className="mono">{pretty(data)}</pre>
        </div>
    );
}