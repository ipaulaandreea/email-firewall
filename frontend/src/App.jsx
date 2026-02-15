import { NavLink, Route, Routes, Navigate } from "react-router-dom";
import IngestionPage from "./pages/IngestionPage.jsx";

export default function App() {
    return (
        <div className="appShell">
            <aside className="sidebar">
                <div className="brand">
                    <div className="brandTitle">Email Firewall</div>
                    <div className="brandSub">Admin Console</div>
                </div>

                <nav className="nav">
                    <NavLink to="/ingestion" className={({ isActive }) => `navItem ${isActive ? "active" : ""}`}>
                        Ingestion
                    </NavLink>
                </nav>
            </aside>

            <main className="content">
                <Routes>
                    <Route path="/" element={<Navigate to="/ingestion" replace />} />
                    <Route path="/ingestion" element={<IngestionPage />} />
                    <Route path="*" element={<NotFound />} />
                </Routes>
            </main>
        </div>
    );
}

function NotFound() {
    return (
        <div className="page">
            <h1>404</h1>
            <p>Pagina nu există.</p>
        </div>
    );
}