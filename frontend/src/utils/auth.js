const KEY = "auth";

function base64UrlDecode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    const pad = str.length % 4;
    if (pad) str += "=".repeat(4 - pad);
    try {
        return decodeURIComponent(
            atob(str)
                .split("")
                .map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0"))
                .join("")
        );
    } catch {
        return null;
    }
}

export function decodeJwt(token) {
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length < 2) return null;
    const json = base64UrlDecode(parts[1]);
    if (!json) return null;
    try {
        return JSON.parse(json);
    } catch {
        return null;
    }
}

export function saveAuth(payload) {
    localStorage.setItem(KEY, JSON.stringify(payload));

    if (payload?.token) localStorage.setItem("token", payload.token);
    if (payload?.role) localStorage.setItem("role", payload.role);
    if (payload?.email) localStorage.setItem("email", payload.email);
}

export function getAuth() {
    const raw = localStorage.getItem(KEY);
    if (raw) {
        try {
            return JSON.parse(raw);
        } catch { /* empty */ }
    }

    const token = localStorage.getItem("token");
    const role = localStorage.getItem("role");
    const email = localStorage.getItem("email");
    if (token || role || email) return { token, role, email };

    return null;
}

export function getToken() {
    return getAuth()?.token || null;
}

export function getRole() {
    const auth = getAuth();
    if (auth?.role) return auth.role;

    const token = auth?.token;
    const payload = decodeJwt(token);
    const role = payload?.role;

    if (typeof role === "string") return role.trim().toUpperCase();
    return null;
}

export function isAuthed() {
    return !!getToken();
}

export function clearAuth() {
    localStorage.removeItem(KEY);
    localStorage.removeItem("token");
    localStorage.removeItem("role");
    localStorage.removeItem("email");
}

export function hasRole(...roles) {
    const role = getRole();
    return !!role && roles.includes(role);
}