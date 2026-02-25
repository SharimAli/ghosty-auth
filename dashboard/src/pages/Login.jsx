import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { auth, token, session } from '../api/index.js';
import { Spinner, Alert } from '../components/UI.jsx';

export default function Login() {
  const navigate = useNavigate();
  const [tab,     setTab]     = useState('login');
  const [form,    setForm]    = useState({ email:'', password:'', username:'', registration_key:'' });
  const [error,   setError]   = useState('');
  const [loading, setLoading] = useState(false);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function handleLogin(e) {
    e.preventDefault(); setError(''); setLoading(true);
    try {
      const res = await auth.login(form.email, form.password);
      token.set(res.data.token); session.set(res.data.user);
      navigate('/dashboard');
    } catch (err) { setError(err.message || 'Login failed.'); }
    finally { setLoading(false); }
  }

  async function handleRegister(e) {
    e.preventDefault(); setError(''); setLoading(true);
    try {
      const payload = { email: form.email, password: form.password, username: form.username };
      if (form.registration_key) payload.registration_key = form.registration_key;
      const r = await fetch('/api/v1/users/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
      if (!r.ok) { const d = await r.json(); throw new Error(d.message || 'Registration failed.'); }
      const res = await auth.login(form.email, form.password);
      token.set(res.data.token); session.set(res.data.user);
      navigate('/dashboard');
    } catch (err) { setError(err.message || 'Registration failed.'); }
    finally { setLoading(false); }
  }

  return (
    <div className="login-bg">
      <div className="login-card">
        <div className="login-logo">
          <h1>👻 GHOSTY<span> AUTH</span></h1>
          <p>License Management Platform</p>
        </div>

        {/* Tabs */}
        <div style={{ display:'flex', marginBottom:24, borderBottom:'1px solid var(--border)' }}>
          {['login','register'].map(t => (
            <button key={t} onClick={() => { setTab(t); setError(''); }}
              style={{ flex:1, padding:'10px 0', background:'none', border:'none',
                borderBottom: tab===t ? '2px solid var(--accent)' : '2px solid transparent',
                color: tab===t ? 'var(--accent)' : 'var(--text-muted)', cursor:'pointer',
                fontFamily:'var(--font-mono)', fontSize:12, fontWeight: tab===t ? 600 : 400,
                textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:'-1px',
                transition:'color 0.15s, border-color 0.15s' }}>
              {t}
            </button>
          ))}
        </div>

        {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}

        {tab === 'login' ? (
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label className="form-label">Email</label>
              <input className="form-input" type="email" placeholder="you@example.com" value={form.email} onChange={e=>set('email',e.target.value)} required autoFocus />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" type="password" placeholder="••••••••" value={form.password} onChange={e=>set('password',e.target.value)} required />
            </div>
            <button className="btn btn-primary" type="submit" disabled={loading}
              style={{ width:'100%', justifyContent:'center', marginTop:8, padding:'11px' }}>
              {loading ? <><Spinner size={14} />&nbsp;Authenticating…</> : 'Sign In →'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleRegister}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <input className="form-input" type="text" placeholder="yourname" value={form.username} onChange={e=>set('username',e.target.value)} required autoFocus />
            </div>
            <div className="form-group">
              <label className="form-label">Email</label>
              <input className="form-input" type="email" placeholder="you@example.com" value={form.email} onChange={e=>set('email',e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" type="password" placeholder="Min 8 chars — upper + lower + digit" value={form.password} onChange={e=>set('password',e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">Registration Key <span className="text-muted">(if required)</span></label>
              <input className="form-input" type="text" placeholder="Leave blank if not required" value={form.registration_key} onChange={e=>set('registration_key',e.target.value)} />
            </div>
            <button className="btn btn-primary" type="submit" disabled={loading}
              style={{ width:'100%', justifyContent:'center', marginTop:8, padding:'11px' }}>
              {loading ? <><Spinner size={14} />&nbsp;Creating account…</> : 'Create Account →'}
            </button>
          </form>
        )}

        <p style={{ textAlign:'center', marginTop:24, fontSize:10, color:'var(--text-dim)', letterSpacing:'0.06em' }}>
          GHOSTY AUTH v1.0.0 — LICENSE AUTHENTICATION SYSTEM
        </p>
      </div>
    </div>
  );
}
