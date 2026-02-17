import { useMemo, useState } from "react";
import { hasRole, getRole } from "../utils/auth";

function pretty(obj) {
    try {
        return JSON.stringify(obj, null, 2);
    } catch {
        return String(obj);
    }
}

export default function IngestionPage() {
    const canBatch = hasRole("ADMIN");
    const canJson = hasRole("ADMIN", "DEVELOPER");
    const canEmlSingle = hasRole("ADMIN", "ANALYST", "DEVELOPER");
    const role = getRole();

    const [jsonForm, setJsonForm] = useState({
        subject: "Test JSON",
        body: "Hello",
        from: "alice@example.com",
        to: "bob@example.com",
    });
    const [jsonLoading, setJsonLoading] = useState(false);
    const [jsonError, setJsonError] = useState(null);
    const [jsonResult, setJsonResult] = useState(null);

    const [emlFile, setEmlFile] = useState(null);
    const [emlLoading, setEmlLoading] = useState(false);
    const [emlError, setEmlError] = useState(null);
    const [emlResult, setEmlResult] = useState(null);

    const [batchFiles, setBatchFiles] = useState([]);
    const [batchLoading, setBatchLoading] = useState(false);
    const [batchError, setBatchError] = useState(null);
    const [batchResult, setBatchResult] = useState(null);

    const hasBatch = useMemo(() => batchFiles && batchFiles.length > 0, [batchFiles]);

    async function fetchJson(url, options = {}) {
        const token = localStorage.getItem("token");

        const headers = new Headers(options.headers || {});
        if (token) headers.set("Authorization", `Bearer ${token}`);

        const res = await fetch(url, { ...options, headers });

        const text = await res.text();
        let data = null;
        try { data = text ? JSON.parse(text) : null; }
        catch { data = text || null; }

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

    async function submitJson(e) {
        const token = localStorage.getItem("token");
        e.preventDefault();
        setJsonError(null);
        setJsonResult(null);

        setJsonLoading(true);
        try {
            const payload = {
                subject: jsonForm.subject,
                bodyText: jsonForm.body,
                from: jsonForm.from,
                to: jsonForm.to ? [jsonForm.to] : [],
            };

            const data = await fetchJson("/api/ingest/json", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify(payload),
            });

            setJsonResult(data);
        } catch (err) {
            setJsonError(err);
        } finally {
            setJsonLoading(false);
        }
    }

    async function submitEml(e) {
        const token = localStorage.getItem("token");
        e.preventDefault();
        setEmlError(null);
        setEmlResult(null);

        if (!emlFile) {
            setEmlError(new Error("Selectează un fișier .eml"));
            return;
        }

        setEmlLoading(true);
        try {
            const fd = new FormData();
            fd.append("file", emlFile);

            const data = await fetchJson("/api/ingest/eml", {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                },
                body: fd,
            });

            setEmlResult(data);
        } catch (err) {
            setEmlError(err);
        } finally {
            setEmlLoading(false);
        }
    }

    async function submitBatch(e) {
        e.preventDefault();

        const token = localStorage.getItem("token");
        if (!token) {
            setBatchError({ message: "Not logged in (missing token)" });
            return;
        }

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

            const res = await fetch("/api/ingest/eml/batch", {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                },
                body: fd,
            });

            const text = await res.text();
            const data = text ? JSON.parse(text) : null;

            if (!res.ok) {
                throw { message: `HTTP ${res.status}`, data };
            }

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
                <h1>Ingestion</h1>
                <p>Upload JSON / EML single / EML batch.</p>
            </div>

            <div className="cardsGrid">
                {canJson && (
                    <section className="card">
                        <div className="cardTitle">Ingest JSON</div>

                        <form onSubmit={submitJson} className="form">
                            <label>
                                Subject
                                <input
                                    value={jsonForm.subject}
                                    onChange={(e) => setJsonForm((s) => ({ ...s, subject: e.target.value }))}
                                />
                            </label>

                            <label>
                                Body
                                <textarea
                                    rows={6}
                                    value={jsonForm.body}
                                    onChange={(e) => setJsonForm((s) => ({ ...s, body: e.target.value }))}
                                />
                            </label>

                            <div className="row">
                                <label>
                                    From
                                    <input
                                        value={jsonForm.from}
                                        onChange={(e) => setJsonForm((s) => ({ ...s, from: e.target.value }))}
                                    />
                                </label>
                                <label>
                                    To (1 email)
                                    <input
                                        value={jsonForm.to}
                                        onChange={(e) => setJsonForm((s) => ({ ...s, to: e.target.value }))}
                                    />
                                </label>
                            </div>

                            <button className="btn" disabled={jsonLoading}>
                                {jsonLoading ? "Sending..." : "Send"}
                            </button>
                        </form>

                        {jsonError && <ErrorBox err={jsonError} />}
                        {jsonResult && <ResultBox title="Response" data={jsonResult} />}
                    </section>
                )}

                {canEmlSingle && (
                    <section className="card">
                        <div className="cardTitle">Ingest EML (single)</div>

                        <form onSubmit={submitEml} className="form">
                            <label>
                                Fișier .eml
                                <input
                                    type="file"
                                    accept=".eml,message/rfc822"
                                    onChange={(e) => setEmlFile(e.target.files?.[0] || null)}
                                />
                            </label>

                            <button className="btn" disabled={emlLoading}>
                                {emlLoading ? "Uploading..." : "Upload"}
                            </button>
                        </form>

                        {emlError && <ErrorBox err={emlError} />}
                        {emlResult && <ResultBox title="Response" data={emlResult} />}
                    </section>
                )}

                {canBatch && (
                    <section className="card span2">
                        <div className="cardTitle">Ingest EML (batch)</div>

                        <form onSubmit={submitBatch} className="form">
                            <label>
                                Fișiere .eml (multiple)
                                <input
                                    type="file"
                                    multiple
                                    accept=".eml,message/rfc822"
                                    onChange={(e) => setBatchFiles(Array.from(e.target.files || []))}
                                />
                            </label>

                            <div className="hint">
                                Selectate: <b>{batchFiles.length}</b>
                            </div>

                            <button className="btn" disabled={batchLoading || batchFiles.length === 0}>
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