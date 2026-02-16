import { Navigate } from "react-router-dom";
import { isAuthed } from "../utils/auth.js";

export default function ProtectedRoute({ children }) {
    if (!isAuthed()) return <Navigate to="/login" replace />;
    return children;
}