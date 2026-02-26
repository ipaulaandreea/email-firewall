import { Routes, Route, Navigate, Outlet, NavLink, useNavigate } from "react-router-dom";
import IngestionPage from "./pages/IngestionPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import RegisterPage from "./pages/RegisterPage.jsx";
import ProtectedRoute from "./components/ProtectedRoute.jsx";
import { clearAuth, isAuthed } from "./utils/auth.js";
import RulesPage from "./pages/RulesPage.jsx";

function AppLayout() {
    const navigate = useNavigate();
    const authed = isAuthed();
    const email = localStorage.getItem("email");
    const role = localStorage.getItem("role");

    function logout() {
        clearAuth();
        navigate("/login", { replace: true });
    }

    return (
        <div className="appShell">
            <aside className="sidebar">
                <div className="brand">
                    <div className="brandTitle">Email Firewall</div>
                    <div className="brandSub">Admin Console</div>
                </div>

                <div className="userBox">
                    <div className="userEmail">{email || "user"}</div>
                    <div className="userRole">{role || "ROLE"}</div>
                </div>

                <nav className="nav">
                    <NavLink to="/ingestion" className={({ isActive }) => `navItem ${isActive ? "active" : ""}`}>
                        Ingestion
                    </NavLink>
                    <NavLink to="/rules" className={({ isActive }) => `navItem ${isActive ? "active" : ""}`}>
                        Rules
                    </NavLink>
                </nav>

                <button className="btn logoutBtn" onClick={logout}>
                    Logout
                </button>
            </aside>

            <main className="content">
                <Outlet />
            </main>
        </div>
    );
}

function AuthLayout() {
    return <Outlet />;
}

function NotFound() {
    return (
        <div className="page">
            <h1>404</h1>
            <p>Pagina nu există.</p>
        </div>
    );
}

export default function App() {
    return (
        <Routes>
            <Route path="/" element={<Navigate to={isAuthed() ? "/ingestion" : "/login"} replace />} />

            <Route element={<AuthLayout />}>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/register" element={<RegisterPage />} />
            </Route>

            <Route
                element={
                    <ProtectedRoute>
                        <AppLayout />
                    </ProtectedRoute>
                }
            >
                <Route path="/ingestion" element={<IngestionPage />} />
                <Route path="/rules" element={<RulesPage />} />
            </Route>

            <Route path="*" element={<NotFound />} />
        </Routes>
    );
}