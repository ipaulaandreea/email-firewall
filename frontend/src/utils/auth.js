export function getToken() {
    return localStorage.getItem("token");
}

export function isAuthed() {
    return !!getToken();
}

export function saveAuth({ token, email, role }) {
    localStorage.setItem("token", token);
    localStorage.setItem("email", email);
    localStorage.setItem("role", role);
}

export function clearAuth() {
    localStorage.removeItem("token");
    localStorage.removeItem("email");
    localStorage.removeItem("role");
}