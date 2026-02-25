import React, { useState, useEffect } from 'react';
import { apps, adminStats, fmtDate } from '../api/index.js';
import { session } from '../api/index.js';
import { PageHeader, LoadingOverlay, Alert, Badge } from '../components/UI.jsx';

function StatCard({ label, value, sub, variant = 'accent' }) {
  return (
    <div className={`stat-card ${variant}`}>
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${variant !== 'accent' ? variant : ''}`}>{value ?? '—'}</div>
      {sub && <div className="stat-meta">{sub}</div>}
    </div>
  );
}

export default function Dashboard() {
  const user    = session.get();
  const isAdmin = user?.role === 'admin';

  const [myApps,  setMyApps]  = useState([]);
  const [stats,   setStats]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const [appsRes, statsRes] = await Promise.all([
          apps.list(),
          isAdmin ? adminStats.get() : Promise.resolve(null),
        ]);
        // Server returns: { success, data: { applications: [...] } }
        const appList = appsRes?.data?.applications ?? [];
        setMyApps(Array.isArray(appList) ? appList : []);
        if (statsRes) setStats(statsRes?.data ?? null);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    })();
  }, [isAdmin]);

  if (loading) return (
    <>
      <PageHeader title="Dashboard" subtitle="Overview" />
      <div className="page-body"><LoadingOverlay /></div>
    </>
  );

  return (
    <>
      <PageHeader title="Dashboard" subtitle={`Welcome back, ${user?.username}`} />
      <div className="page-body animate-fade">
        {error && <Alert type="error" onDismiss={() => setError('')}>{error}</Alert>}

        {isAdmin && stats && (
          <>
            <div style={{ marginBottom: 8 }}><span className="tag">SYSTEM OVERVIEW</span></div>
            <div className="stat-grid" style={{ marginBottom: 28 }}>
              <StatCard label="Total Users"  value={stats.users?.total}          sub="registered sellers"    variant="accent" />
              <StatCard label="Applications" value={stats.applications?.total}   sub="across all sellers"    variant="blue" />
              <StatCard label="License Keys" value={stats.keys?.total}           sub={`${stats.keys?.active ?? 0} active`} variant="accent" />
              <StatCard label="Banned Keys"  value={stats.keys?.banned}          sub="revoked licenses"      variant="red" />
              <StatCard label="Auth (24h)"   value={stats.logs?.auth_last_24h}   sub="authentication events" variant="yellow" />
            </div>
          </>
        )}

        <div style={{ marginBottom: 8 }}><span className="tag">MY APPLICATIONS</span></div>

        {myApps.length === 0 ? (
          <div className="card">
            <div className="card-body" style={{ textAlign:'center', padding:48 }}>
              <div style={{ fontSize:32, marginBottom:12 }}>◈</div>
              <p style={{ color:'var(--text-muted)', marginBottom:16 }}>No applications yet.</p>
              <a href="/settings" className="btn btn-primary" style={{ textDecoration:'none' }}>+ Create Application</a>
            </div>
          </div>
        ) : (
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(280px, 1fr))', gap:12 }}>
            {myApps.map(app => (
              <div key={app.id} className="card">
                <div className="card-header">
                  <span className="card-title">{app.name}</span>
                  <Badge status={app.is_active ? 'active' : 'banned'}>{app.is_active ? 'active' : 'disabled'}</Badge>
                </div>
                <div className="card-body">
                  {app.description && <p style={{ color:'var(--text-muted)', fontSize:12, marginBottom:12 }}>{app.description}</p>}
                  <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
                    <div>
                      <div style={{ fontSize:9, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:2 }}>App ID</div>
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:10, color:'var(--text-muted)' }}>{app.id?.slice(0,8)}…</div>
                    </div>
                    <div>
                      <div style={{ fontSize:9, color:'var(--text-dim)', textTransform:'uppercase', letterSpacing:'0.1em', marginBottom:2 }}>Version</div>
                      <div style={{ fontFamily:'var(--font-mono)', fontSize:11 }}>{app.version || '1.0.0'}</div>
                    </div>
                  </div>
                  <div style={{ marginTop:12, paddingTop:12, borderTop:'1px solid var(--border)', fontSize:10, color:'var(--text-dim)' }}>
                    Created {fmtDate(app.created_at || app.createdAt)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
