import React, { useState, useEffect } from 'react';
import { apps as appsApi, profile, adminApps } from '../api/index.js';
import { session, fmtDate } from '../api/index.js';
import {
  PageHeader, Badge, Alert, Modal, Spinner, ConfirmModal, CopyButton, EmptyState,
} from '../components/UI.jsx';

/* ─── Create App Modal ───────────────────────────────────────── */
function CreateAppModal({ onClose, onDone }) {
  const [form,    setForm]    = useState({ name:'', description:'' });
  const [secret,  setSecret]  = useState('');
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function handle(e) {
    e.preventDefault(); setError(''); setLoading(true);
    try {
      const res = await appsApi.create({ name: form.name.trim(), description: form.description.trim() || undefined });
      setSecret(res.data.secret);
      onDone();
    } catch (err) { setError(err.message); setLoading(false); }
  }

  if (secret) return (
    <Modal title="Application Created" onClose={onClose}
      footer={<button className="btn btn-primary" onClick={onClose}>I've saved the secret</button>}>
      <Alert type="warn">
        This secret will <strong>never be shown again</strong>. Copy it now and store it securely.
      </Alert>
      <div className="form-group" style={{ marginTop:8 }}>
        <label className="form-label">App Secret (HMAC Key)</label>
        <div style={{ display:'flex', alignItems:'center', gap:8, padding:'10px 12px',
          background:'var(--bg-2)', border:'1px solid var(--accent)', borderRadius:'var(--r)' }}>
          <code style={{ flex:1, fontFamily:'var(--font-mono)', fontSize:11, color:'var(--accent)',
            wordBreak:'break-all', lineHeight:1.6 }}>{secret}</code>
          <CopyButton text={secret} label="Copy" />
        </div>
      </div>
    </Modal>
  );

  return (
    <Modal title="New Application" onClose={onClose}
      footer={<>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handle} disabled={loading}>{loading ? <Spinner /> : 'Create'}</button>
      </>}>
      {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}
      <form onSubmit={handle}>
        <div className="form-group">
          <label className="form-label">Name</label>
          <input className="form-input" type="text" placeholder="My Software v2" value={form.name}
            onChange={e => set('name', e.target.value)} required maxLength={64} autoFocus />
        </div>
        <div className="form-group">
          <label className="form-label">Description <span className="text-muted">optional</span></label>
          <textarea className="form-textarea" placeholder="Short description of this application…"
            value={form.description} onChange={e => set('description', e.target.value)} maxLength={512} rows={2} />
        </div>
      </form>
    </Modal>
  );
}

/* ─── Change Password Modal ──────────────────────────────────── */
function ChangePasswordModal({ onClose }) {
  const [form,    setForm]    = useState({ current_password:'', new_password:'' });
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const [done,    setDone]    = useState(false);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function handle(e) {
    e.preventDefault(); setError(''); setLoading(true);
    try {
      await profile.update(form);
      setDone(true);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }

  return (
    <Modal title="Change Password" onClose={onClose}
      footer={!done && <>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handle} disabled={loading}>{loading ? <Spinner /> : 'Update Password'}</button>
      </>}>
      {done ? <Alert type="success">Password updated successfully.</Alert> : (
        <>
          {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}
          <form onSubmit={handle}>
            <div className="form-group">
              <label className="form-label">Current Password</label>
              <input className="form-input" type="password" value={form.current_password} onChange={e => set('current_password', e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">New Password</label>
              <input className="form-input" type="password" placeholder="Min 8 chars — upper + lower + digit" value={form.new_password} onChange={e => set('new_password', e.target.value)} required />
            </div>
          </form>
        </>
      )}
    </Modal>
  );
}

/* ─── Main Page ──────────────────────────────────────────────── */
export default function Settings() {
  const user    = session.get();
  const isAdmin = user?.role === 'admin';

  const [myApps,    setMyApps]    = useState([]);
  const [allApps,   setAllApps]   = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [showPw,     setShowPw]     = useState(false);
  const [confirmDel, setConfirmDel] = useState(null);
  const [delLoading, setDelLoading] = useState(false);

  async function loadApps() {
    setLoading(true);
    try {
      const [myRes, adminRes] = await Promise.all([
        appsApi.list(),
        isAdmin ? adminApps.list() : Promise.resolve(null),
      ]);
      setMyApps(myRes.data || []);
      if (adminRes) setAllApps(adminRes.data || []);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }

  useEffect(() => { loadApps(); }, []);

  async function handleDelete() {
    setDelLoading(true);
    try { await appsApi.delete(confirmDel); await loadApps(); }
    catch (err) { setError(err.message); }
    finally { setDelLoading(false); setConfirmDel(null); }
  }

  async function handleToggle(id) {
    try { await adminApps.toggle(id); await loadApps(); }
    catch (err) { setError(err.message); }
  }

  return (
    <>
      <PageHeader title="Settings" subtitle="Applications & account" />
      <div className="page-body animate-fade">
        {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}

        {/* ── My Applications ──────────────────────────────── */}
        <div className="flex-between mb-16">
          <span className="tag">MY APPLICATIONS</span>
          <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(true)}>+ New Application</button>
        </div>

        {loading ? (
          <div className="card"><div style={{ padding:40, textAlign:'center', color:'var(--text-dim)' }}>Loading…</div></div>
        ) : myApps.length === 0 ? (
          <div className="card">
            <EmptyState icon="◈" message="No applications yet.">
              <button className="btn btn-primary" onClick={() => setShowCreate(true)}>Create Your First App</button>
            </EmptyState>
          </div>
        ) : (
          <div style={{ display:'flex', flexDirection:'column', gap:10, marginBottom:28 }}>
            {myApps.map(app => (
              <div key={app.id} className="card">
                <div className="card-header">
                  <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                    <span style={{ fontWeight:700, fontFamily:'var(--font-display)', fontSize:13 }}>{app.name}</span>
                    <Badge status={app.is_active ? 'active' : 'banned'}>{app.is_active ? 'active' : 'disabled'}</Badge>
                    {app.version && <span className="tag">{app.version}</span>}
                  </div>
                  <div style={{ display:'flex', gap:6 }}>
                    <button className="btn btn-sm btn-ghost" style={{ color:'var(--red)' }}
                      onClick={() => setConfirmDel(app.id)}>Delete</button>
                  </div>
                </div>
                <div style={{ padding:'12px 18px', display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:16 }}>
                  <div>
                    <div style={{ fontSize:9, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:3 }}>App ID</div>
                    <div style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-muted)', display:'flex', alignItems:'center', gap:6 }}>
                      {app.id.slice(0,18)}…
                      <CopyButton text={app.id} />
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize:9, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:3 }}>Created</div>
                    <div style={{ fontSize:11, color:'var(--text-muted)' }}>{fmtDate(app.createdAt || app.created_at)}</div>
                  </div>
                  <div>
                    <div style={{ fontSize:9, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:3 }}>Description</div>
                    <div style={{ fontSize:11, color:'var(--text-muted)' }}>{app.description || '—'}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── Admin: All Applications ───────────────────────── */}
        {isAdmin && allApps.length > 0 && (
          <>
            <div className="divider" />
            <div className="flex-between mb-16">
              <span className="tag">ALL APPLICATIONS (ADMIN)</span>
            </div>
            <div className="card">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Name</th><th>Owner</th><th>Status</th><th>Created</th><th>Actions</th></tr>
                  </thead>
                  <tbody>
                    {allApps.map(app => (
                      <tr key={app.id}>
                        <td style={{ fontWeight:500 }}>{app.name}</td>
                        <td style={{ fontSize:12, color:'var(--text-muted)' }}>@{app.owner?.username || '—'}</td>
                        <td><Badge status={app.is_active ? 'active' : 'banned'}>{app.is_active ? 'active' : 'disabled'}</Badge></td>
                        <td style={{ fontSize:11, color:'var(--text-muted)' }}>{fmtDate(app.createdAt)}</td>
                        <td>
                          <button className="btn btn-sm btn-ghost" onClick={() => handleToggle(app.id)}>
                            {app.is_active ? 'Disable' : 'Enable'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {/* ── Account ───────────────────────────────────────── */}
        <div className="divider" />
        <div className="mb-16"><span className="tag">ACCOUNT</span></div>
        <div className="card" style={{ maxWidth:480 }}>
          <div className="card-body">
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, marginBottom:16 }}>
              <div>
                <div className="form-label">Username</div>
                <div style={{ fontFamily:'var(--font-mono)', fontSize:13 }}>@{user?.username}</div>
              </div>
              <div>
                <div className="form-label">Role</div>
                <Badge status={user?.role}>{user?.role}</Badge>
              </div>
              <div style={{ gridColumn:'1/-1' }}>
                <div className="form-label">Email</div>
                <div style={{ fontFamily:'var(--font-mono)', fontSize:13, color:'var(--text-muted)' }}>{user?.email || '—'}</div>
              </div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowPw(true)}>Change Password</button>
          </div>
        </div>
      </div>

      {showCreate && <CreateAppModal onClose={() => setShowCreate(false)} onDone={loadApps} />}
      {showPw     && <ChangePasswordModal onClose={() => setShowPw(false)} />}
      {confirmDel && (
        <ConfirmModal title="Delete Application" danger
          message="Permanently delete this application and ALL its license keys? This cannot be undone."
          onConfirm={handleDelete} onCancel={() => setConfirmDel(null)} loading={delLoading} />
      )}
    </>
  );
}
