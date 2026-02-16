import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { isAuthed, saveAuth } from "../utils/auth.js";
import "./auth.css";

export default function LoginPage() {
    const navigate = useNavigate();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    if (isAuthed()) return <Navigate to="/ingestion" replace />;

    async function onSubmit(e) {
        e.preventDefault();
        setError(null);
        setLoading(true);

        try {
            const res = await fetch("http://localhost:8080/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });

            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
                throw new Error(data.message || "Login failed");
            }

            saveAuth(data);
            navigate("/ingestion", { replace: true });
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="authWrap">
            <div className="authCard">
                <h1>Login</h1>
                <p className="muted">Accesează consola Email Firewall.</p>

                <form onSubmit={onSubmit} className="form">
                    <label>
                        Email
                        <input
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="admin@example.com"
                            required
                        />
                    </label>

                    <label>
                        Password
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="••••••••"
                            required
                        />
                    </label>

                    {error && <div className="alert">{error}</div>}

                    <button className="btn" type="submit" disabled={loading}>
                        {loading ? "Logging in..." : "Login"}
                    </button>
                </form>

                <p className="muted">
                    Nu ai cont? <Link to="/register">Register</Link>
                </p>
            </div>
        </div>
    );
}