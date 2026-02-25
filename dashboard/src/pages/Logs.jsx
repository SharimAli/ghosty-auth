import React, { useState, useEffect, useCallback } from 'react';
import { session, adminLogs, apps, fmtDate } from '../api/index.js';
import {
  PageHeader, Badge, LoadingOverlay, Alert, Modal, Spinner,
  ConfirmModal, Pagination, EmptyState, AppSelector,
} from '../components/UI.jsx';

const LIMIT  = 50;
const ACTIONS = ['AUTH_INIT','AUTH_VALIDATE','AUTH_LOGOUT','KEY_BANNED','KEY_UNBANNED','HWID_RESET','KEY_EXTENDED','USER_LOGIN','USER_LOGIN_FAILED','USER_BANNED','USER_REGISTERED'];

export default function Logs() {
  const user    = session.get();
  const isAdmin = user?.role === 'admin';

  const [myApps,   setMyApps]   = useState([]);
  const [appId,    setAppId]    = useState('');
  const [data,     setData]     = useState({ data: [], meta: { pagination: { total:0, total_pages:1 } } });
  const [page,     setPage]     = useState(1);
  const [action,   setAction]   = useState('');
  const [status,   setStatus]   = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');
  const [showPurge, setShowPurge]  = useState(false);
  const [purgeDays, setPurgeDays]  = useState(90);
  const [purgeLoading, setPurgeLoading] = useState(false);

  // Load apps (for filter selector)
  useEffect(() => {
    apps.list().then(r => {
      const list = r.data || [];
      setMyApps(list);
    }).catch(() => {});
  }, []);

  const load = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true); setError('');
    try {
      const params = { page, limit: LIMIT };
      if (appId)    params.app_id = appId;
      if (action)   params.action = action;
      if (status)   params.status = status;
      if (ipFilter) params.ip     = ipFilter;
      const res = await adminLogs.list(params);
      setData(res);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }, [isAdmin, page, appId, action, status, ipFilter]);

  useEffect(() => { load(); }, [load]);

  async function handlePurge() {
    setPurgeLoading(true);
    try {
      await adminLogs.purge(Number(purgeDays));
      setShowPurge(false);
      await load();
    } catch (err) { setError(err.message); }
    finally { setPurgeLoading(false); }
  }

  const rows = data.data || [];
  const pag  = data.meta?.pagination || { total:0, total_pages:1 };

  if (!isAdmin) return (
    <>
      <PageHeader title="Logs" subtitle="Authentication events" />
      <div className="page-body">
        <div className="alert info">Admin access required to view system logs.</div>
      </div>
    </>
  );

  return (
    <>
      <PageHeader
        title="Logs"
        subtitle={`${pag.total} events`}
        actions={
          <button className="btn btn-ghost btn-sm" style={{ color:'var(--red)', borderColor:'var(--red)' }}
            onClick={() => setShowPurge(true)}>
            ⚠ Purge Old Logs
          </button>
        }
      />

      <div className="page-body animate-fade">
        {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}

        {/* Filters */}
        <div className="toolbar" style={{ flexWrap:'wrap', gap:8 }}>
          <AppSelector apps={myApps} value={appId} onChange={v => { setAppId(v); setPage(1); }} />
          <select className="form-select" value={action} onChange={e => { setAction(e.target.value); setPage(1); }}
            style={{ width:190 }}>
            <option value="">All actions</option>
            {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <select className="form-select" value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}
            style={{ width:130 }}>
            <option value="">All status</option>
            <option value="success">success</option>
            <option value="failed">failed</option>
            <option value="blocked">blocked</option>
          </select>
          <input className="search-input" placeholder="Filter by IP…" value={ipFilter}
            style={{ width:160 }}
            onChange={e => { setIpFilter(e.target.value); setPage(1); }} />
        </div>

        {loading ? <LoadingOverlay /> : rows.length === 0 ? (
          <div className="card"><EmptyState icon="≡" message="No log entries found" /></div>
        ) : (
          <div className="card">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Status</th>
                    <th>IP</th>
                    <th>Key</th>
                    <th>HWID</th>
                    <th>Reason</th>
                    <th>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(log => (
                    <tr key={log.id}>
                      <td style={{ fontSize:11, color:'var(--text-muted)', whiteSpace:'nowrap' }}>{fmtDate(log.created_at || log.createdAt)}</td>
                      <td><span className="tag" style={{ fontSize:9, letterSpacing:'0.06em' }}>{log.action}</span></td>
                      <td><Badge status={log.status}>{log.status}</Badge></td>
                      <td style={{ fontFamily:'var(--font-mono)', fontSize:11 }}>{log.ip || '—'}</td>
                      <td style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-muted)' }}>
                        {log.license_key ? log.license_key : '—'}
                      </td>
                      <td style={{ fontFamily:'var(--font-mono)', fontSize:11, color:'var(--text-muted)' }}>
                        {log.hwid || '—'}
                      </td>
                      <td style={{ fontSize:11 }}>
                        {log.reason
                          ? <span style={{ color:'var(--red)' }}>{log.reason}</span>
                          : <span className="text-dim">—</span>}
                      </td>
                      <td style={{ fontSize:11, color:'var(--text-muted)' }}>{log.note || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={page} totalPages={pag.total_pages} total={pag.total} limit={LIMIT} onChange={setPage} />
          </div>
        )}
      </div>

      {/* Purge Modal */}
      {showPurge && (
        <Modal title="Purge Old Logs" onClose={() => setShowPurge(false)}
          footer={<>
            <button className="btn btn-ghost" onClick={() => setShowPurge(false)}>Cancel</button>
            <button className="btn btn-danger" onClick={handlePurge} disabled={purgeLoading}>
              {purgeLoading ? <Spinner /> : 'Purge Logs'}
            </button>
          </>}>
          <Alert type="warn">This permanently deletes logs older than the specified number of days.</Alert>
          <div className="form-group">
            <label className="form-label">Delete logs older than (days)</label>
            <input className="form-input" type="number" min={1} value={purgeDays}
              onChange={e => setPurgeDays(e.target.value)} />
          </div>
        </Modal>
      )}
    </>
  );
}
