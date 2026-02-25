import React, { useEffect } from 'react';
import { copyText } from '../api/index.js';

export function Modal({ title, onClose, children, footer, size = '' }) {
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', h);
    return () => document.removeEventListener('keydown', h);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${size}`}>
        <div className="modal-header">
          <span className="modal-title">{title}</span>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

export function Badge({ status, children }) {
  return (
    <span className={`badge ${status}`}>
      <span className="badge-dot" />
      {children || status}
    </span>
  );
}

export function Spinner({ size = 16 }) {
  return <span className="spinner" style={{ width: size, height: size }} />;
}

export function LoadingOverlay({ text = 'Loading...' }) {
  return <div className="loading-overlay"><Spinner size={18} /><span>{text}</span></div>;
}

export function Alert({ type = 'error', children, onDismiss }) {
  const icons = { error: '✕', success: '✓', warn: '⚠', info: 'i' };
  return (
    <div className={`alert ${type}`}>
      <span style={{ fontWeight: 700, flexShrink: 0 }}>{icons[type]}</span>
      <span style={{ flex: 1 }}>{children}</span>
      {onDismiss && <button onClick={onDismiss} style={{ background:'none',border:'none',cursor:'pointer',color:'inherit',fontSize:14,padding:0 }}>✕</button>}
    </div>
  );
}

export function CopyButton({ text, label }) {
  const [copied, setCopied] = React.useState(false);
  async function handleCopy() { await copyText(text); setCopied(true); setTimeout(() => setCopied(false), 1800); }
  return <button className="copy-btn" onClick={handleCopy} title="Copy">{copied ? '✓' : (label || '⎘')}</button>;
}

export function KeyDisplay({ value }) {
  return <div className="key-display"><span className="key-code">{value}</span><CopyButton text={value} /></div>;
}

export function Pagination({ page, totalPages, total, limit, onChange }) {
  const start = (page - 1) * limit + 1;
  const end   = Math.min(page * limit, total);
  const pages = Array.from({ length: Math.min(totalPages, 5) }, (_, i) => Math.max(1, Math.min(page - 2, totalPages - 4)) + i);
  return (
    <div className="pagination">
      <span className="pagination-meta">{total > 0 ? `${start}–${end} of ${total}` : '0 results'}</span>
      <button className="page-btn" onClick={() => onChange(page - 1)} disabled={page <= 1}>‹</button>
      {pages.map(p => <button key={p} className={`page-btn${p === page ? ' current' : ''}`} onClick={() => onChange(p)}>{p}</button>)}
      <button className="page-btn" onClick={() => onChange(page + 1)} disabled={page >= totalPages}>›</button>
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="page-header">
      <div>
        <div className="page-title">{title}</div>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
      </div>
      {actions && <div style={{ display:'flex', gap:8 }}>{actions}</div>}
    </div>
  );
}

export function EmptyState({ icon = '◈', message = 'No data found', children }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <p>{message}</p>
      {children && <div style={{ marginTop:16 }}>{children}</div>}
    </div>
  );
}

export function ConfirmModal({ title, message, danger, onConfirm, onCancel, loading }) {
  return (
    <Modal title={title} onClose={onCancel}
      footer={<>
        <button className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        <button className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`} onClick={onConfirm} disabled={loading}>
          {loading ? <Spinner /> : 'Confirm'}
        </button>
      </>}
    >
      <p style={{ color:'var(--text-muted)', fontSize:13 }}>{message}</p>
    </Modal>
  );
}

export function AppSelector({ apps, value, onChange }) {
  if (!apps || apps.length === 0) return <div className="alert info">No applications yet. Create one in Settings.</div>;
  return (
    <select className="form-select" value={value} onChange={e => onChange(e.target.value)} style={{ maxWidth:260 }}>
      <option value="">— Select application —</option>
      {apps.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
    </select>
  );
}
