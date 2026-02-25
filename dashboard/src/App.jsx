import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { token, session } from './api/index.js';
import Sidebar  from './components/Sidebar.jsx';

import Login     from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Keys      from './pages/Keys.jsx';
import Users     from './pages/Users.jsx';
import Logs      from './pages/Logs.jsx';
import Settings  from './pages/Settings.jsx';

/* ─── Auth guard ─────────────────────────────────────────────── */
function RequireAuth({ children }) {
  const t = token.get();
  const u = session.get();
  if (!t || !u) return <Navigate to="/login" replace />;
  return children;
}

/* ─── Admin guard ────────────────────────────────────────────── */
function RequireAdmin({ children }) {
  const u = session.get();
  if (u?.role !== 'admin') return <Navigate to="/dashboard" replace />;
  return children;
}

/* ─── Shell layout (sidebar + main) ─────────────────────────── */
function AppShell({ children }) {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="main-content">{children}</main>
    </div>
  );
}

/* ─── Session expiry watcher ─────────────────────────────────── */
function SessionWatcher() {
  const navigate  = useNavigate();
  const location  = useLocation();

  useEffect(() => {
    // Re-check token on every route change
    if (location.pathname !== '/login') {
      const t = token.get();
      if (!t) navigate('/login', { replace: true });
    }
  }, [location.pathname, navigate]);

  return null;
}

/* ─── App root ───────────────────────────────────────────────── */
export default function App() {
  return (
    <BrowserRouter>
      <SessionWatcher />
      <Routes>

        {/* Public */}
        <Route path="/login" element={<Login />} />

        {/* Protected */}
        <Route path="/dashboard" element={
          <RequireAuth>
            <AppShell><Dashboard /></AppShell>
          </RequireAuth>
        } />

        <Route path="/keys" element={
          <RequireAuth>
            <AppShell><Keys /></AppShell>
          </RequireAuth>
        } />

        <Route path="/logs" element={
          <RequireAuth>
            <AppShell><Logs /></AppShell>
          </RequireAuth>
        } />

        <Route path="/settings" element={
          <RequireAuth>
            <AppShell><Settings /></AppShell>
          </RequireAuth>
        } />

        {/* Admin-only */}
        <Route path="/users" element={
          <RequireAuth>
            <RequireAdmin>
              <AppShell><Users /></AppShell>
            </RequireAdmin>
          </RequireAuth>
        } />

        {/* Redirects */}
        <Route path="/"   element={<Navigate to="/dashboard" replace />} />
        <Route path="*"   element={<Navigate to="/dashboard" replace />} />

      </Routes>
    </BrowserRouter>
  );
}
