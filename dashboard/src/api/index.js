/**
 * GHOSTY Auth — API Client
 * Centralised fetch wrappers for all server endpoints.
 */

const BASE = (import.meta.env.VITE_API_URL || '') + '/api/v1';

export const token = {
  get:   ()  => localStorage.getItem('ghosty_token'),
  set:   (t) => localStorage.setItem('ghosty_token', t),
  clear: ()  => localStorage.removeItem('ghosty_token'),
};

export const session = {
  get:   ()  => { try { return JSON.parse(localStorage.getItem('ghosty_user') || 'null'); } catch { return null; } },
  set:   (u) => localStorage.setItem('ghosty_user', JSON.stringify(u)),
  clear: ()  => localStorage.removeItem('ghosty_user'),
};

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  const t = token.get();
  if (t) headers['Authorization'] = `Bearer ${t}`;
  const res = await fetch(`${BASE}${path}`, {
    method, headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || `HTTP ${res.status}`);
    err.code = data.code; err.status = res.status; err.data = data;
    throw err;
  }
  return data;
}

const get   = (path)       => request('GET',    path);
const post  = (path, body) => request('POST',   path, body);
const patch = (path, body) => request('PATCH',  path, body);
const del   = (path, body) => request('DELETE', path, body);

export const auth        = { login: (e,p) => post('/users/login', { email: e, password: p }), logout: () => { token.clear(); session.clear(); } };
export const profile     = { me: () => get('/users/me'), update: (d) => patch('/users/me', d) };
export const apps        = { list: () => get('/users/applications'), create: (d) => post('/users/applications', d), delete: (id) => del(`/users/applications/${id}`) };
export const keys        = {
  list:      (appId, p={}) => get(`/keys?${new URLSearchParams({app_id:appId,...p})}`),
  getOne:    (id)           => get(`/keys/${id}`),
  generate:  (d)            => post('/keys/generate', d),
  ban:       (d)            => post('/keys/ban', d),
  unban:     (d)            => post('/keys/unban', d),
  resetHwid: (d)            => post('/keys/reset-hwid', d),
  extend:    (d)            => post('/keys/extend', d),
  delete:    (id)           => del(`/keys/${id}`),
};
export const adminUsers  = {
  list:   (p={}) => get(`/admin/users?${new URLSearchParams(p)}`),
  getOne: (id)   => get(`/admin/users/${id}`),
  update: (id,d) => patch(`/admin/users/${id}`, d),
  ban:    (d)    => post('/admin/users/ban', d),
  unban:  (d)    => post('/admin/users/unban', d),
  delete: (id)   => del(`/admin/users/${id}`),
};
export const adminApps   = { list: (p={}) => get(`/admin/applications?${new URLSearchParams(p)}`), toggle: (id) => post(`/admin/applications/${id}/toggle`) };
export const adminLogs   = { list: (p={}) => get(`/admin/logs?${new URLSearchParams(p)}`), purge: (d) => del('/admin/logs', { older_than_days: d }) };
export const adminStats  = { get: () => get('/admin/stats') };

export function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('en-US', { month:'short', day:'numeric', year:'numeric', hour:'2-digit', minute:'2-digit', hour12:false });
}
export function fmtDateShort(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
}
export function copyText(text) {
  return navigator.clipboard.writeText(text).catch(() => {
    const el = document.createElement('textarea'); el.value = text;
    document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
  });
}
