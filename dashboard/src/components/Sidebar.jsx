import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { auth, session } from '../api/index.js';

const NAV = [
  { to: '/dashboard', icon: '◈', label: 'Dashboard' },
  { to: '/keys',      icon: '⌗', label: 'License Keys' },
  { to: '/logs',      icon: '≡',  label: 'Logs' },
  { to: '/settings',  icon: '⚙', label: 'Settings' },
];

const ADMIN_NAV = [
  { to: '/users', icon: '◉', label: 'Users' },
];

export default function Sidebar() {
  const navigate = useNavigate();
  const user     = session.get();
  const isAdmin  = user?.role === 'admin';

  function handleLogout() {
    auth.logout();
    navigate('/login');
  }

  const initials = user?.username
    ? user.username.slice(0, 2).toUpperCase()
    : '??';

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <span className="logo-ghost">👻</span>
        <span>GHOSTY<span className="logo-accent"> AUTH</span></span>
      </div>

      {/* Nav */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Navigation</div>
        {NAV.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
          >
            <span className="nav-icon">{icon}</span>
            {label}
          </NavLink>
        ))}

        {isAdmin && (
          <>
            <div className="nav-section-label" style={{ marginTop: 12 }}>Admin</div>
            {ADMIN_NAV.map(({ to, icon, label }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
              >
                <span className="nav-icon">{icon}</span>
                {label}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      {/* User footer */}
      <div className="sidebar-footer">
        <div className="sidebar-user">
          <div className="user-avatar">{initials}</div>
          <div className="user-info">
            <div className="user-name">{user?.username || 'unknown'}</div>
            <div className="user-role">{user?.role || 'seller'}</div>
          </div>
          <button className="logout-btn" onClick={handleLogout} title="Log out">✕</button>
        </div>
      </div>
    </aside>
  );
}
