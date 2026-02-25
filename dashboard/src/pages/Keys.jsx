import React, { useState, useEffect, useCallback } from 'react';
import { apps, keys as keysApi, fmtDate, fmtDateShort } from '../api/index.js';
import {
  PageHeader, Badge, Spinner, LoadingOverlay, Alert, Modal,
  ConfirmModal, Pagination, EmptyState, AppSelector, KeyDisplay,
} from '../components/UI.jsx';

const LIMIT = 50;

function GenerateModal({ appId, onClose, onDone }) {
  const [form,    setForm]    = useState({ quantity:1, expires_in_days:'', note:'' });
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const set = (k,v) => setForm(f => ({...f,[k]:v}));

  async function handleGenerate(e) {
    e.preventDefault(); setError(''); setLoading(true);
    try {
      const payload = { app_id: appId, quantity: Number(form.quantity) };
      if (form.expires_in_days) payload.expires_in_days = Number(form.expires_in_days);
      if (form.note.trim())     payload.note = form.note.trim();
      const res = await keysApi.generate(payload);
      setResult(res.data);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }

  if (result) {
    const keyList = Array.isArray(result) ? result : (result.keys ?? []);
    return (
      <Modal title="Keys Generated" onClose={() => { onDone(); onClose(); }}
        footer={<button className="btn btn-primary" onClick={() => { onDone(); onClose(); }}>Done</button>}>
        <Alert type="success">{keyList.length} key{keyList.length !== 1 ? 's' : ''} generated.</Alert>
        <div style={{ maxHeight:320, overflowY:'auto', display:'flex', flexDirection:'column', gap:6 }}>
          {keyList.map((k,i) => (
            <div key={i} style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
              padding:'8px 10px', background:'var(--bg-2)', borderRadius:'var(--r)', border:'1px solid var(--border)' }}>
              <KeyDisplay value={k.key} />
              <span style={{ fontSize:10, color:'var(--text-muted)' }}>{k.expires_at ? fmtDateShort(k.expires_at) : 'No expiry'}</span>
            </div>
          ))}
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Generate License Keys" onClose={onClose}
      footer={<>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handleGenerate} disabled={loading}>{loading ? <Spinner /> : 'Generate'}</button>
      </>}>
      {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}
      <form onSubmit={handleGenerate}>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Quantity (1–100)</label>
            <input className="form-input" type="number" min={1} max={100} value={form.quantity}
              onChange={e => set('quantity',e.target.value)} required />
          </div>
          <div className="form-group">
            <label className="form-label">Expires In (days) <span className="text-muted">optional</span></label>
            <input className="form-input" type="number" min={1} max={36500} placeholder="Never"
              value={form.expires_in_days} onChange={e => set('expires_in_days',e.target.value)} />
          </div>
        </div>
        <div className="form-group">
          <label className="form-label">Note <span className="text-muted">optional</span></label>
          <input className="form-input" type="text" placeholder="e.g. Batch A, order #42"
            value={form.note} onChange={e => set('note',e.target.value)} maxLength={255} />
        </div>
      </form>
    </Modal>
  );
}

function ExtendModal({ keyId, onClose, onDone }) {
  const [days, setDays] = useState(30);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  async function handle() {
    setError(''); setLoading(true);
    try { await keysApi.extend({ key_id: keyId, days: Number(days) }); onDone(); onClose(); }
    catch (err) { setError(err.message); setLoading(false); }
  }

  return (
    <Modal title="Extend Key Expiry" onClose={onClose}
      footer={<>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={handle} disabled={loading}>{loading ? <Spinner /> : 'Extend'}</button>
      </>}>
      {error && <Alert type="error">{error}</Alert>}
      <div className="form-group">
        <label className="form-label">Extend by (days)</label>
        <input className="form-input" type="number" min={1} max={36500} value={days} onChange={e => setDays(e.target.value)} />
      </div>
    </Modal>
  );
}

function BanModal({ keyId, onClose, onDone }) {
  const [reason,  setReason]  = useState('');
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  async function handle() {
    setError(''); setLoading(true);
    try { await keysApi.ban({ key_id: keyId, reason: reason.trim() || undefined }); onDone(); onClose(); }
    catch (err) { setError(err.message); setLoading(false); }
  }

  return (
    <Modal title="Ban License Key" onClose={onClose}
      footer={<>
        <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        <button className="btn btn-danger" onClick={handle} disabled={loading}>{loading ? <Spinner /> : 'Ban Key'}</button>
      </>}>
      {error && <Alert type="error">{error}</Alert>}
      <Alert type="warn">This will immediately block authentication for this key.</Alert>
      <div className="form-group">
        <label className="form-label">Reason <span className="text-muted">optional</span></label>
        <input className="form-input" type="text" placeholder="e.g. Refund, TOS violation"
          value={reason} onChange={e => setReason(e.target.value)} maxLength={255} />
      </div>
    </Modal>
  );
}

export default function Keys() {
  const [myApps,     setMyApps]     = useState([]);
  const [appId,      setAppId]      = useState('');
  const [rows,       setRows]       = useState([]);
  const [pagination, setPagination] = useState({ total:0, total_pages:1 });
  const [page,       setPage]       = useState(1);
  const [search,     setSearch]     = useState('');
  const [status,     setStatus]     = useState('');
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState('');

  const [showGen,    setShowGen]    = useState(false);
  const [banTarget,  setBanTarget]  = useState(null);
  const [extTarget,  setExtTarget]  = useState(null);
  const [confirmDel, setConfirmDel] = useState(null);
  const [confirmAct, setConfirmAct] = useState(null);
  const [actLoading, setActLoading] = useState(false);

  useEffect(() => {
    apps.list().then(r => {
      const list = r?.data?.applications ?? [];
      setMyApps(Array.isArray(list) ? list : []);
      if (list.length > 0 && !appId) setAppId(list[0].id);
    }).catch(() => {});
  }, []);

  const loadKeys = useCallback(async () => {
    if (!appId) return;
    setLoading(true); setError('');
    try {
      const params = { page, limit: LIMIT };
      if (search) params.search = search;
      if (status) params.status = status;
      const res = await keysApi.list(appId, params);
      // Server returns: { success, data: { keys: [...], pagination: {...} } }
      const d = res?.data ?? {};
      setRows(Array.isArray(d.keys) ? d.keys : []);
      setPagination(d.pagination ?? { total:0, total_pages:1 });
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }, [appId, page, search, status]);

  useEffect(() => { loadKeys(); }, [loadKeys]);

  async function handleUnban(keyId) {
    setActLoading(true);
    try { await keysApi.unban({ key_id: keyId }); await loadKeys(); }
    catch (err) { setError(err.message); }
    finally { setActLoading(false); setConfirmAct(null); }
  }

  async function handleResetHwid(keyId) {
    setActLoading(true);
    try { await keysApi.resetHwid({ key_id: keyId }); await loadKeys(); }
    catch (err) { setError(err.message); }
    finally { setActLoading(false); setConfirmAct(null); }
  }

  async function handleDelete() {
    setActLoading(true);
    try { await keysApi.delete(confirmDel); await loadKeys(); }
    catch (err) { setError(err.message); }
    finally { setActLoading(false); setConfirmDel(null); }
  }

  // Determine status from key fields
  function keyStatus(k) {
    if (k.is_banned) return 'banned';
    if (k.expires_at && new Date(k.expires_at) < new Date()) return 'expired';
    return 'active';
  }

  return (
    <>
      <PageHeader title="License Keys"
        subtitle={appId ? `${pagination.total} keys` : 'Select an application'}
        actions={appId && <button className="btn btn-primary" onClick={() => setShowGen(true)}>+ Generate Keys</button>}
      />
      <div className="page-body animate-fade">
        {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}

        <div className="toolbar">
          <AppSelector apps={myApps} value={appId} onChange={v => { setAppId(v); setPage(1); }} />
          {appId && <>
            <input className="search-input" placeholder="Search key…" value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }} />
            <select className="form-select" value={status} onChange={e => { setStatus(e.target.value); setPage(1); }} style={{ width:130 }}>
              <option value="">All status</option>
              <option value="active">Active</option>
              <option value="banned">Banned</option>
              <option value="expired">Expired</option>
            </select>
          </>}
        </div>

        {!appId ? (
          <div className="card"><EmptyState icon="⌗" message="Select an application to view keys" /></div>
        ) : loading ? <LoadingOverlay /> : rows.length === 0 ? (
          <div className="card">
            <EmptyState icon="⌗" message="No keys found">
              <button className="btn btn-primary" onClick={() => setShowGen(true)}>Generate Keys</button>
            </EmptyState>
          </div>
        ) : (
          <div className="card">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Key</th><th>Status</th><th>HWID</th><th>Expires</th><th>Last Used</th><th>Note</th><th>Actions</th></tr>
                </thead>
                <tbody>
                  {rows.map(k => {
                    const st = keyStatus(k);
                    return (
                      <tr key={k.id}>
                        <td><KeyDisplay value={k.key} /></td>
                        <td>
                          <Badge status={st}>{st}</Badge>
                          {k.ban_reason && <div style={{ fontSize:9, color:'var(--text-dim)', marginTop:2 }}>{k.ban_reason}</div>}
                        </td>
                        <td>
                          {k.hwid
                            ? <span className="tag" style={{ color:'var(--accent)', borderColor:'var(--accent)' }}>bound</span>
                            : <span className="text-muted" style={{ fontSize:11 }}>unbound</span>}
                        </td>
                        <td style={{ color: st === 'expired' ? 'var(--red)' : 'inherit', fontSize:11 }}>
                          {k.expires_at ? fmtDateShort(k.expires_at) : <span className="text-muted">Never</span>}
                        </td>
                        <td style={{ fontSize:11, color:'var(--text-muted)' }}>
                          {k.last_used_at ? fmtDate(k.last_used_at) : <span className="text-dim">Never</span>}
                        </td>
                        <td style={{ fontSize:11, color:'var(--text-muted)' }}>{k.note || '—'}</td>
                        <td>
                          <div style={{ display:'flex', gap:4 }}>
                            {st === 'banned'
                              ? <button className="btn btn-sm btn-ghost" onClick={() => setConfirmAct({ type:'unban', keyId:k.id })}>Unban</button>
                              : <button className="btn btn-sm btn-ghost" style={{ color:'var(--red)', borderColor:'var(--red)' }} onClick={() => setBanTarget(k.id)}>Ban</button>}
                            <button className="btn btn-sm btn-ghost" onClick={() => setExtTarget(k.id)}>Extend</button>
                            {k.hwid && <button className="btn btn-sm btn-ghost" onClick={() => setConfirmAct({ type:'hwid', keyId:k.id })}>↺ HWID</button>}
                            <button className="btn btn-sm btn-ghost" style={{ color:'var(--red)' }} onClick={() => setConfirmDel(k.id)}>✕</button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <Pagination page={page} totalPages={pagination.total_pages} total={pagination.total} limit={LIMIT} onChange={setPage} />
          </div>
        )}
      </div>

      {showGen   && <GenerateModal appId={appId} onClose={() => setShowGen(false)} onDone={loadKeys} />}
      {banTarget && <BanModal keyId={banTarget} onClose={() => setBanTarget(null)} onDone={loadKeys} />}
      {extTarget && <ExtendModal keyId={extTarget} onClose={() => setExtTarget(null)} onDone={loadKeys} />}
      {confirmAct?.type === 'unban' && (
        <ConfirmModal title="Unban Key" message="Remove the ban? Key will be able to authenticate again."
          onConfirm={() => handleUnban(confirmAct.keyId)} onCancel={() => setConfirmAct(null)} loading={actLoading} />
      )}
      {confirmAct?.type === 'hwid' && (
        <ConfirmModal title="Reset HWID" danger message="Clear hardware ID binding? Key can be activated on a new machine."
          onConfirm={() => handleResetHwid(confirmAct.keyId)} onCancel={() => setConfirmAct(null)} loading={actLoading} />
      )}
      {confirmDel && (
        <ConfirmModal title="Delete Key" danger message="Permanently delete this key? Cannot be undone."
          onConfirm={handleDelete} onCancel={() => setConfirmDel(null)} loading={actLoading} />
      )}
    </>
  );
}
