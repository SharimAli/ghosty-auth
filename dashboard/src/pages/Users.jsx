import React, { useState, useEffect, useCallback } from 'react';
import { adminUsers, fmtDate } from '../api/index.js';
import {
  PageHeader, Badge, LoadingOverlay, Alert, Modal, Spinner,
  ConfirmModal, Pagination, EmptyState,
} from '../components/UI.jsx';

const LIMIT = 50;

function BanModal({ user, onClose, onDone }) {
  const [reason, setReason]   = useState('');
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  async function handle() {
    setError(''); setLoading(true);
    try { await adminUsers.ban({ user_id: user.id, reason: reason.trim() || undefined }); onDone(); onClose(); }
    catch (err) { setError(err.message); setLoading(false); }
  }

  return (
    <Modal title={`Ban @${user.username}`} onClose={onClose}
      footer={<>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-danger" onClick={handle} disabled={loading}>{loading ? <Spinner /> : 'Ban User'}</button>
      </>}>
      {error && <Alert type="error">{error}</Alert>}
      <Alert type="warn">This will immediately block all logins for this account.</Alert>
      <div className="form-group">
        <label className="form-label">Reason <span className="text-muted">optional</span></label>
        <input className="form-input" type="text" placeholder="e.g. Abuse, TOS violation"
          value={reason} onChange={e => setReason(e.target.value)} maxLength={255} />
      </div>
    </Modal>
  );
}

function EditModal({ user, onClose, onDone }) {
  const [form,    setForm]    = useState({ role: user.role, new_password: '' });
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  async function handle() {
    setError(''); setLoading(true);
    try {
      const payload = {};
      if (form.role !== user.role)  payload.role = form.role;
      if (form.new_password.trim()) payload.new_password = form.new_password;
      if (!Object.keys(payload).length) { setError('No changes made.'); setLoading(false); return; }
      await adminUsers.update(user.id, payload);
      onDone(); onClose();
    } catch (err) { setError(err.message); setLoading(false); }
  }

  return (
    <Modal title={`Edit @${user.username}`} onClose={onClose}
      footer={<>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handle} disabled={loading}>{loading ? <Spinner /> : 'Save Changes'}</button>
      </>}>
      {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}
      <div className="form-group">
        <label className="form-label">Role</label>
        <select className="form-select" value={form.role} onChange={e => set('role', e.target.value)}>
          <option value="seller">seller</option>
          <option value="admin">admin</option>
        </select>
      </div>
      <div className="form-group">
        <label className="form-label">Force New Password <span className="text-muted">optional</span></label>
        <input className="form-input" type="text" placeholder="Leave blank to keep current"
          value={form.new_password} onChange={e => set('new_password', e.target.value)} />
      </div>
    </Modal>
  );
}

export default function Users() {
  const [rows,         setRows]         = useState([]);
  const [pagination,   setPagination]   = useState({ total:0, total_pages:1 });
  const [page,         setPage]         = useState(1);
  const [search,       setSearch]       = useState('');
  const [roleFilter,   setRoleFilter]   = useState('');
  const [bannedFilter, setBannedFilter] = useState('');
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState('');

  const [banTarget,    setBanTarget]    = useState(null);
  const [editTarget,   setEditTarget]   = useState(null);
  const [confirmDel,   setConfirmDel]   = useState(null);
  const [confirmUnban, setConfirmUnban] = useState(null);
  const [actLoading,   setActLoading]   = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError('');
    try {
      const params = { page, limit: LIMIT };
      if (search)       params.search    = search;
      if (roleFilter)   params.role      = roleFilter;
      if (bannedFilter) params.is_banned = bannedFilter;
      const res = await adminUsers.list(params);
      // Server returns: { success, data: { users: [...], pagination: {...} } }
      const d = res?.data ?? {};
      setRows(Array.isArray(d.users) ? d.users : []);
      setPagination(d.pagination ?? { total:0, total_pages:1 });
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }, [page, search, roleFilter, bannedFilter]);

  useEffect(() => { load(); }, [load]);

  async function handleUnban(userId) {
    setActLoading(true);
    try { await adminUsers.unban({ user_id: userId }); await load(); }
    catch (err) { setError(err.message); }
    finally { setActLoading(false); setConfirmUnban(null); }
  }

  async function handleDelete() {
    setActLoading(true);
    try { await adminUsers.delete(confirmDel); await load(); }
    catch (err) { setError(err.message); }
    finally { setActLoading(false); setConfirmDel(null); }
  }

  return (
    <>
      <PageHeader title="Users" subtitle={`${pagination.total} registered accounts`} />
      <div className="page-body animate-fade">
        {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}

        <div className="toolbar">
          <input className="search-input" placeholder="Search username or email…" value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }} />
          <select className="form-select" value={roleFilter} onChange={e => { setRoleFilter(e.target.value); setPage(1); }} style={{ width:120 }}>
            <option value="">All roles</option>
            <option value="seller">Seller</option>
            <option value="admin">Admin</option>
          </select>
          <select className="form-select" value={bannedFilter} onChange={e => { setBannedFilter(e.target.value); setPage(1); }} style={{ width:130 }}>
            <option value="">All status</option>
            <option value="false">Active</option>
            <option value="true">Banned</option>
          </select>
        </div>

        {loading ? <LoadingOverlay /> : rows.length === 0 ? (
          <div className="card"><EmptyState icon="◉" message="No users found" /></div>
        ) : (
          <div className="card">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Last Login</th><th>Joined</th><th>Actions</th></tr>
                </thead>
                <tbody>
                  {rows.map(u => (
                    <tr key={u.id}>
                      <td style={{ fontWeight:500 }}>@{u.username}</td>
                      <td style={{ color:'var(--text-muted)', fontSize:12 }}>{u.email}</td>
                      <td><Badge status={u.role}>{u.role}</Badge></td>
                      <td>
                        {u.is_banned
                          ? <><Badge status="banned">banned</Badge>{u.ban_reason && <div style={{fontSize:9,color:'var(--text-dim)',marginTop:2}}>{u.ban_reason}</div>}</>
                          : <Badge status="active">active</Badge>}
                      </td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{fmtDate(u.last_login_at)}</td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{fmtDate(u.createdAt)}</td>
                      <td>
                        <div style={{ display:'flex', gap:4 }}>
                          <button className="btn btn-sm btn-ghost" onClick={() => setEditTarget(u)}>Edit</button>
                          {u.is_banned
                            ? <button className="btn btn-sm btn-ghost" onClick={() => setConfirmUnban(u.id)}>Unban</button>
                            : <button className="btn btn-sm btn-ghost" style={{ color:'var(--yellow)' }} onClick={() => setBanTarget(u)}>Ban</button>}
                          <button className="btn btn-sm btn-ghost" style={{ color:'var(--red)' }} onClick={() => setConfirmDel(u.id)}>✕</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} totalPages={pagination.total_pages} total={pagination.total} limit={LIMIT} onChange={setPage} />
          </div>
        )}
      </div>

      {banTarget    && <BanModal user={banTarget} onClose={() => setBanTarget(null)} onDone={load} />}
      {editTarget   && <EditModal user={editTarget} onClose={() => setEditTarget(null)} onDone={load} />}
      {confirmUnban && <ConfirmModal title="Unban User" message="Remove the ban from this account?"
        onConfirm={() => handleUnban(confirmUnban)} onCancel={() => setConfirmUnban(null)} loading={actLoading} />}
      {confirmDel   && <ConfirmModal title="Delete User" danger
        message="Permanently delete this user and all their data? Cannot be undone."
        onConfirm={handleDelete} onCancel={() => setConfirmDel(null)} loading={actLoading} />}
    </>
  );
}
