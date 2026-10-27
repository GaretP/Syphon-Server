'use strict';
/* Syphon web UI. Plain JS, no build step, no external requests. All text is inserted with
   textContent / text nodes, never innerHTML, so titles and file names cannot inject markup. */

const OCTO =
  '<svg viewBox="0 0 64 64" aria-hidden="true"><path d="M32 5C19 5 12 14 12 25c0 7 3 11 6 14h28c3-3 6-7 6-14C52 14 45 5 32 5z" fill="currentColor"/><g fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round"><path d="M19 38c-1 8-6 11-11 9"/><path d="M25 40c0 8-2 13-8 16"/><path d="M32 40v13c0 4 4 5 6 2"/><path d="M39 40c0 8 2 13 8 16"/><path d="M45 38c1 8 6 11 11 9"/></g><circle cx="24.500" cy="25" r="4.200" fill="#fff"/><circle cx="39.500" cy="25" r="4.200" fill="#fff"/><circle cx="25.500" cy="26" r="2.100" fill="#1b1030"/><circle cx="40.500" cy="26" r="2.100" fill="#1b1030"/></svg>';

/* DOM turns a null child into the text "null"; drop those instead. */
const _replaceChildren = Element.prototype.replaceChildren;
Element.prototype.replaceChildren = function (...k) { return _replaceChildren.apply(this, k.filter((x) => x != null && x !== false)); };

const S = { me: null, status: null, timers: [], sync: null, review: 0, lowMode: false, page: '', lib: { q: '', kind: '', scroll: 0, keep: false } };

// ------------------------------------------------------------------ helpers
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'html') el.innerHTML = v; // only ever called with the static OCTO constant
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'for') el.htmlFor = v;
    else if (['value', 'checked', 'disabled', 'selected', 'type', 'min', 'max', 'step', 'placeholder', 'href', 'src', 'readOnly', 'multiple', 'accept', 'download', 'title', 'autocomplete', 'rows', 'name', 'id'].includes(k)) {
      try { el[k] = v; } catch { el.setAttribute(k, v); }
    } else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const $ = (s, r = document) => r.querySelector(s);

function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / 1024 ** i).toFixed(i ? 1 : 0) + ' ' + u[i];
}
function fmtTime(s) {
  s = Math.max(0, Math.floor(s));
  const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60), ss = s % 60;
  return (hh ? hh + ':' + String(mm).padStart(2, '0') : mm) + ':' + String(ss).padStart(2, '0');
}
function ago(ts) {
  if (!ts) return 'never';
  const d = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (d < 10) return 'just now';
  if (d < 90) return d + 's ago';
  if (d < 5400) return Math.round(d / 60) + ' min ago';
  if (d < 129600) return Math.round(d / 3600) + ' h ago';
  return Math.round(d / 86400) + ' d ago';
}
function hue(str) {
  let x = 7;
  for (const c of String(str).toLowerCase()) x = (x * 31 + c.charCodeAt(0)) >>> 0;
  return 250 + (x % 95); // violets to plums: posters stay inside the palette
}
function epLabel(it) {
  if (it.season != null && it.episode != null) return 'S' + String(it.season).padStart(2, '0') + 'E' + String(it.episode).padStart(2, '0');
  if (it.episode != null) return 'Ep ' + it.episode;
  return '';
}
function toast(msg, kind) {
  const t = h('div', { class: 'toast ' + (kind || ''), role: 'status' }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), kind === 'bad' ? 7000 : 3800);
}
function copy(text) {
  const done = () => toast('Copied', 'ok');
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const t = h('textarea', { value: text });
  document.body.append(t);
  t.select();
  try { document.execCommand('copy'); done(); } catch { toast('Select the text and copy it manually', 'bad'); }
  t.remove();
}

async function api(path, opts = {}) {
  const o = { method: opts.method || 'GET', headers: { 'x-requested-with': 'syphon' }, credentials: 'same-origin' };
  if (opts.raw !== undefined) {
    o.body = opts.raw;
  } else if (opts.body !== undefined) {
    o.headers['content-type'] = 'application/json';
    o.body = JSON.stringify(opts.body);
  }
  let r;
  try {
    r = await fetch(path, o);
  } catch {
    const e = new Error(navigator.onLine === false
      ? 'This device is offline. Check your internet or Wi-Fi and try again.'
      : 'Cannot reach this Syphon node right now. It may be restarting, or the connection dropped. Try again in a moment.');
    e.status = 0;
    throw e;
  }
  let data = null;
  try { data = await r.json(); } catch { /* empty or not JSON */ }
  if (r.status === 401 && !opts.quiet && S.me) {
    S.me = null;
    boot();
  }
  if (!r.ok) {
    const generic = r.status >= 500 ? 'The node hit a problem handling that. Try again; if it keeps happening, check the node log.'
      : r.status === 404 ? 'That no longer exists.'
      : r.status === 403 ? 'You are not allowed to do that from here.'
      : r.status === 413 ? 'That is too large.'
      : r.status === 429 ? 'Too many tries. Wait a moment and try again.'
      : 'That did not work (error ' + r.status + ').';
    const e = new Error((data && data.error) || generic);
    e.status = r.status;
    throw e;
  }
  return data;
}
window.addEventListener('unhandledrejection', (ev) => {
  ev.preventDefault();
  const m = ev.reason && ev.reason.message;
  if (m) toast(m, 'bad');
});
window.addEventListener('offline', () => toast('You are offline. Playback and changes will resume when the connection returns.', 'bad'));
window.addEventListener('online', () => toast('Back online', 'ok'));
async function act(fn, okMsg) {
  try {
    const r = await fn();
    if (okMsg) toast(okMsg, 'ok');
    return r;
  } catch (e) {
    toast(e.message, 'bad');
    return undefined;
  }
}
function poll(fn, ms) {
  fn();
  S.timers.push(setInterval(fn, ms));
}
function clearTimers() {
  S.timers.forEach(clearInterval);
  S.timers = [];
}
function field(label, input, hint) {
  return h('label', { class: 'field' }, h('span', null, label), input, hint ? h('small', null, hint) : null);
}
function modal(title, body, onclose) {
  const close = () => { scrim.remove(); document.removeEventListener('keydown', esc); if (onclose) onclose(); };
  const esc = (e) => { if (e.key === 'Escape') close(); };
  const scrim = h('div', { class: 'scrim', onclick: (e) => { if (e.target === scrim) close(); } },
    h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
      h('header', null, h('h2', null, title), h('button', { class: 'btn small ghost', 'aria-label': 'Close', onclick: close }, 'Close')),
      body));
  document.addEventListener('keydown', esc);
  document.body.append(scrim);
  return close;
}

// ------------------------------------------------------------------ theme, boot, shell
const ICON_SUN = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const ICON_MOON = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/></svg>';
const ICON_VAULT = '<svg viewBox="0 0 48 48" aria-hidden="true"><rect x="6" y="9" width="36" height="30" rx="4"/><circle cx="24" cy="24" r="7"/><path d="M24 17v-3M24 34v-3M17 24h-3M34 24h-3M12 39v3M36 39v3"/></svg>';

function currentTheme() { return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'; }
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('syphon-theme', t); } catch { /* private mode: the choice just will not stick */ }
  document.querySelectorAll('.theme-toggle').forEach((b) => paintThemeBtn(b));
}
function paintThemeBtn(b) {
  const light = currentTheme() === 'light';
  b.innerHTML = light ? ICON_MOON : ICON_SUN; // static icon constants only
  b.title = light ? 'Switch to dark mode' : 'Switch to light mode';
  b.setAttribute('aria-label', b.title);
}
function themeButton() {
  const b = h('button', { class: 'btn ghost icon-btn theme-toggle', type: 'button', onclick: () => setTheme(currentTheme() === 'light' ? 'dark' : 'light') });
  paintThemeBtn(b);
  return b;
}

function deviceName() {
  const u = navigator.userAgent || '';
  const b = /Edg\//.test(u) ? 'Edge' : /Firefox\//.test(u) ? 'Firefox' : /Chrome\//.test(u) ? 'Chrome' : /Safari\//.test(u) ? 'Safari' : 'Browser';
  const o = /Android/.test(u) ? 'Android' : /iPhone|iPad/.test(u) ? 'iOS' : /Windows/.test(u) ? 'Windows' : /Mac OS/.test(u) ? 'Mac' : /Linux/.test(u) ? 'Linux' : 'device';
  return b + ' on ' + o;
}
const atHome = () => !!(S.me && S.me.zone === 'lan');
// at home, or away through the VPN box: fast enough for the original quality
const fastLink = () => !!(S.me && (S.me.zone === 'lan' || S.me.fast));

async function boot() {
  clearTimers();
  clearInterval(S.chromeTimer);
  try { S.status = await api('/api/status', { quiet: true }); } catch { S.status = { name: null, locked: true, zone: 'remote' }; }
  try { S.me = await api('/api/me', { quiet: true }); } catch { S.me = null; }
  // inside the Syphon app, signing in happens on the app's own "Who's watching?" page
  if (!S.me && IN_APP) { location.href = '/__app/profiles'; return; }
  if (!S.me) return renderLogin();
  if (tvActive()) return route();
  renderShell();
  route();
}

function loginFrame(...kids) {
  document.getElementById('app').replaceChildren(
    h('div', { class: 'login-wrap' },
      h('div', { class: 'corner' }, themeButton()),
      h('div', { class: 'login' },
        h('div', { class: 'flame', html: OCTO }),
        h('h1', null, 'Syphon'),
        ...kids)));
}

function renderLogin(msg, opts = {}) {
  const locked = S.status && S.status.locked;
  const away = S.status && S.status.zone !== 'lan';
  const err = h('div', { class: 'err', role: 'alert' }, msg || '');
  const user = h('input', { type: 'text', value: opts.user || '', autocomplete: 'username', id: 'u', 'aria-label': 'Your name' });
  const pw = h('input', { type: 'password', autocomplete: 'current-password', id: 'p', 'aria-label': 'Password' });
  const code = h('input', { type: 'text', autocomplete: 'one-time-code', id: 'c', placeholder: '6-digit code', 'aria-label': 'Authenticator code' });
  const needTotp = !!opts.needTotp;
  const go = h('button', { class: 'btn primary', type: 'submit' }, locked ? 'Unlock' : 'Sign in');
  const form = h('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      go.disabled = true;
      go.textContent = 'Signing in…';
      try {
        const r = await api('/api/login', { method: 'POST', quiet: true, body: { user: user.value, password: pw.value, totp: needTotp ? code.value : undefined, device_name: deviceName() } });
        if (r.need === 'totp') return renderLogin('', { user: user.value, needTotp: true, pw: pw.value });
        if (r.pending) return renderPending(r.pending, user.value);
        boot();
      } catch (ex) {
        err.textContent = ex.message;
        go.disabled = false;
        go.textContent = locked ? 'Unlock' : 'Sign in';
        pw.value = '';
        (needTotp ? code : pw).focus();
      }
    },
  },
  field('Your name', user), field('Password', pw), needTotp ? field('Code from your authenticator app', code) : null, err, go);
  if (needTotp && opts.pw) pw.value = opts.pw;
  loginFrame(
    h('p', { class: 'sub' }, locked
      ? 'This node is locked. Your library stays encrypted until its owner signs in.'
      : away ? 'Sign in to your library.' : 'Welcome back.'),
    h('div', { class: 'login-card' }, form),
    h('p', { class: 'note' }, away
      ? 'You are connecting from outside the home network. A new device needs a second confirmation.'
      : 'Your password unlocks the library only in memory, only while you are signed in.'));
  (user.value ? (needTotp ? code : pw) : user).focus();
}

function renderPending(p, userName) {
  const msg = h('p', { class: 'muted' }, 'Waiting for approval…');
  loginFrame(
    h('p', { class: 'sub' }, 'One more step: approve this device from home.'),
    h('div', { class: 'login-card' },
      h('div', { class: 'approval-code', 'aria-label': 'Approval code' }, p.code),
      h('p', { class: 'muted' }, 'Open Syphon on a device at home, find this code under the notice that says someone is signing in, and press Approve. The request expires in 10 minutes.'),
      msg,
      h('button', { class: 'btn ghost', onclick: () => { clearInterval(S.pollTimer); renderLogin('', { user: userName }); } }, 'Cancel')));
  clearInterval(S.pollTimer);
  S.pollTimer = setInterval(async () => {
    try {
      const r = await api('/api/login/poll', { method: 'POST', body: { id: p.id, secret: p.secret }, quiet: true });
      if (r.state === 'ok') { clearInterval(S.pollTimer); boot(); }
      else if (r.state === 'denied') { clearInterval(S.pollTimer); renderLogin('That sign-in was declined at home.', { user: userName }); }
      else if (r.state === 'expired') { clearInterval(S.pollTimer); renderLogin('The request expired. Sign in again to get a new code.', { user: userName }); }
    } catch { /* keep trying: the connection may be slow */ }
  }, 3000);
}

const NAV = [
  ['library', 'Library', 'viewer'],
  ['add', 'Add', 'contributor'],
  ['vault', 'Vault', 'viewer', true],
  ['review', 'Review', 'owner'],
  ['mesh', 'Mesh', 'owner'],
];
const RANK = { viewer: 1, contributor: 2, owner: 3 };

// A connection code for the Syphon app: lets someone connect the first time even when they are away from home.
function connectCodeBox() {
  const who = h('input', { type: 'text', placeholder: 'Who it is for, e.g. Mia\'s laptop', 'aria-label': 'Who the code is for', maxlength: '60' });
  const out = h('div');
  const make = h('button', { class: 'btn small', onclick: async () => {
    make.disabled = true;
    try {
      const r = await api('/api/connect/code', { method: 'POST', body: { name: who.value.trim() } });
      const ta = h('textarea', { readOnly: true, rows: 3, class: 'code-box', 'aria-label': 'Connection code' }, r.code);
      out.replaceChildren(ta, h('div', { class: 'row' }, h('button', { class: 'btn small', onclick: () => copy(r.code) }, 'Copy')),
        h('p', { class: 'faint' }, r.has_key
          ? 'This code includes a device key for the outside address (listed under Device keys, where you can remove it). Give it only to that person.'
          : 'Give it only to the person it is for.'));
    } catch (e) { toast(e.message, 'bad'); } finally { make.disabled = false; }
  } }, 'Make a connection code');
  return h('div', null, h('h3', null, 'Syphon app, from anywhere'),
    h('p', { class: 'muted' }, 'In the Syphon app, "I\'m away from home" takes a connection code: it holds this node\'s name and addresses, so the app can connect the first time even away from home. The person still signs in with their own name and password, and the first sign-in from outside still needs your approval or their authenticator code.'),
    h('div', { class: 'row' }, who, make), out);
}

function renderShell() {
  const nav = h('nav', { class: 'nav', 'aria-label': 'Main' },
    NAV.filter(([, , r, homeOnly]) => RANK[S.me.role] >= RANK[r] && (!homeOnly || atHome())).map(([id, label]) =>
      h('a', { href: '#/' + id, id: 'nav-' + id }, label, id === 'review' ? h('span', { class: 'badge hidden', id: 'review-badge' }, '0') : null)));
  document.getElementById('app').replaceChildren(
    h('header', { class: 'topbar' },
      h('a', { class: 'brand', href: '#/library' }, h('span', { html: OCTO }), 'Syphon'),
      nav,
      h('div', { class: 'chips', id: 'chips' }),
      themeButton(),
      h('div', { class: 'who-wrap', id: 'who-wrap' })),
    h('div', { id: 'alerts' }),
    h('main', { id: 'view' }));
  refreshWho();
  refreshChrome();
  S.chromeTimer = setInterval(refreshChrome, 8000);
}

async function logout() {
  await api('/api/logout', { method: 'POST', quiet: true }).catch(() => {});
  clearInterval(S.chromeTimer);
  S.me = null;
  if (IN_APP) { location.href = '/__app/profiles'; return; }
  boot();
}

/* Things that need the owner's attention, wherever they are in the app: someone signing in from
   outside, and nodes asking to connect. */
async function drawAlerts() {
  const box = $('#alerts');
  if (!box || !atHome()) return;
  const items = [];
  try {
    const a = await api('/api/approvals', { quiet: true });
    for (const p of a.pending) {
      items.push(h('div', { class: 'notice warn' },
        h('div', { class: 'grow' }, h('strong', null, p.user + ' is signing in from outside your home network'), h('div', { class: 'muted' }, 'Device: ' + p.device_name + ' · code ' + p.code + '. Only approve it if you started this and the code matches.')),
        h('button', { class: 'btn small primary', onclick: () => act(() => api('/api/approvals/' + p.id + '/approve', { method: 'POST' }), 'Approved').then(drawAlerts) }, 'Approve'),
        h('button', { class: 'btn small danger', onclick: () => act(() => api('/api/approvals/' + p.id + '/deny', { method: 'POST' }), 'Declined').then(drawAlerts) }, 'Decline')));
    }
    if (S.me.role === 'owner') {
      const pr = await api('/api/pair', { quiet: true });
      for (const r of pr.incoming) {
        items.push(h('div', { class: 'notice' },
          h('div', { class: 'grow' }, h('strong', null, r.name + ' wants to connect to your mesh'), h('div', { class: 'muted' }, 'Their fingerprint is ' + r.fingerprint + '. Check it with them if you are not sure it is really them.')),
          h('button', { class: 'btn small primary', onclick: () => act(() => api('/api/pair/requests/' + r.id + '/accept', { method: 'POST' }), r.name + ' is now connected').then(() => { drawAlerts(); if (location.hash.startsWith('#/mesh')) route(); }) }, 'Accept'),
          h('button', { class: 'btn small danger', onclick: () => act(() => api('/api/pair/requests/' + r.id + '/deny', { method: 'POST' }), 'Declined').then(drawAlerts) }, 'Decline')));
      }
    }
  } catch { /* signed out or locked: the next request deals with it */ }
  box.replaceChildren(...items);
}

async function refreshChrome() {
  const chips = $('#chips');
  if (!chips || !S.me) return;
  const parts = [];
  if (S.me.role === 'owner') {
    try {
      S.sync = await api('/api/sync', { quiet: true });
      const t = S.sync.tor;
      if (S.sync.node.transport === 'tor') {
        // Tor only shows up when something is wrong; when it works there is nothing to see
        if (t.bootstrap < 100) parts.push(h('span', { class: 'chip hide-sm ' + (t.error ? 'bad' : 'warn'), title: 'Syphon reaches your other houses through Tor' }, h('i'), t.error ? 'Tor problem' : 'Tor connecting ' + t.bootstrap + '%'));
      }
      const on = S.sync.policy.enabled && !S.sync.gate;
      parts.push(h('span', { class: 'chip ' + (on ? 'ok' : 'bad') }, h('i'), on ? 'Sync on' : S.sync.policy.enabled ? 'Sync paused' : 'Sync off'));
      const rv = await api('/api/review', { quiet: true });
      S.review = rv.items.length;
      const b = $('#review-badge');
      if (b) { b.textContent = S.review; b.classList.toggle('hidden', !S.review); }
    } catch { /* locked or expired: the next request handles it */ }
  }
  chips.replaceChildren(...parts);
  drawAlerts();
}

function route() {
  clearTimers();
  document.querySelectorAll('.modal').forEach((m) => m.parentElement.remove());
  const [name, ...rest] = location.hash.replace(/^#\/?/, '').split('/');
  const page = name || 'library';
  // the TV view has its own full-screen layout; leaving it brings the normal page back
  if (page === 'tv') return tvRoute(rest);
  if (document.body.classList.contains('tv')) tvLeave();
  if (!$('#view')) renderShell();
  // leaving the library for a show or a film: remember where you were so "← Library" brings you back to the same spot
  if (S.page === 'library' && (page === 'show' || page === 'watch')) { S.lib.keep = true; S.lib.scroll = window.scrollY; }
  else if (page !== 'library' && page !== 'show' && page !== 'watch') S.lib.keep = false;
  S.page = page;
  const view = $('#view');
  if (!view) return;
  document.querySelectorAll('.nav a').forEach((a) => a.classList.toggle('on', a.id === 'nav-' + (page === 'watch' || page === 'show' ? 'library' : page)));
  const arg = rest.join('/');
  const table = { library: viewLibrary, show: viewShow, watch: viewWatch, add: viewAdd, vault: viewVault, review: viewReview, mesh: viewMesh, settings: viewSettings };
  const fn = table[page] || viewLibrary;
  const meta = NAV.find((n) => n[0] === page);
  if (meta && RANK[S.me.role] < RANK[meta[2]]) return view.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'Not available'), 'Your account cannot open this page.'));
  fn(view, arg).catch((e) => view.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'Something went wrong'), e.message)));
}
window.addEventListener('hashchange', () => { if (S.me) route(); });

// ------------------------------------------------------------------ library
// Loose episodes of one show share a `group` (computed by the node from the title, however the
// files were named), so twenty uploaded episodes become one poster, then a page with seasons.
const seasonOf = (it) => (it.season != null ? it.season : it.episode != null ? 1 : 0);
const byEpisode = (a, b) => seasonOf(a) - seasonOf(b) || (a.episode || 0) - (b.episode || 0) || a.title.localeCompare(b.title);
function commonest(list) {
  const n = new Map();
  list.forEach((v) => n.set(v, (n.get(v) || 0) + 1));
  return [...n.entries()].sort((a, b) => b[1] - a[1])[0][0];
}
function finishGroup(g) {
  g.eps.sort(byEpisode);
  g.title = commonest(g.eps.map((e) => e.title));
  g.kind = commonest(g.eps.map((e) => e.kind));
  g.year = (g.eps.find((e) => e.year) || {}).year || null;
  g.seasons = [...new Set(g.eps.map(seasonOf))].filter((s) => s > 0).length;
  g.id = g.key;
  return g;
}
function groupItems(items) {
  const out = [];
  const map = new Map();
  for (const it of items) {
    if (it.kind === 'movie' || !it.group) { out.push({ id: it.id, key: null, title: it.title, year: it.year, kind: it.kind, eps: [it], seasons: 0 }); continue; }
    let g = map.get(it.group);
    if (!g) { g = { key: it.group, eps: [] }; map.set(it.group, g); out.push(g); }
    g.eps.push(it);
  }
  out.forEach((g) => { if (g.key) finishGroup(g); });
  return out;
}
const showSummary = (g) => (g.seasons > 1 ? g.seasons + ' seasons · ' : '') + g.eps.length + (g.eps.length === 1 ? ' episode' : ' episodes');

// A person's picture, or their initial on a colour when they have not chosen one.
function avatarEl(user, ver, size) {
  const a = h('span', { class: 'avatar', 'aria-hidden': 'true' });
  a.style.setProperty('--h', hue(user));
  if (size) a.style.setProperty('--s', size + 'px');
  const initial = () => a.replaceChildren(document.createTextNode((user || '?').slice(0, 1).toUpperCase()));
  if (ver) {
    const img = h('img', { src: '/api/avatar/' + encodeURIComponent(user) + '?v=' + ver, alt: '' });
    img.addEventListener('error', initial);
    a.append(img);
  } else initial();
  return a;
}

// Shrink a chosen picture to a 256px square in the browser before it is sent.
function shrinkPicture(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const side = Math.min(img.width, img.height), n = 256;
      const c = document.createElement('canvas');
      c.width = n; c.height = n;
      c.getContext('2d').drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, n, n);
      URL.revokeObjectURL(url);
      c.toBlob((b) => (b ? resolve(b) : reject(new Error('That picture could not be read.'))), 'image/jpeg', 0.88);
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Choose a PNG, JPEG or WebP picture.')); };
    img.src = url;
  });
}

function refreshWho() {
  const slot = $('#who-wrap');
  if (!slot || !S.me) return;
  const menu = h('div', { class: 'who-menu hidden', role: 'menu', id: 'who-menu' },
    h('div', { class: 'who-head' }, h('strong', null, S.me.user), h('small', null, S.me.role)),
    h('a', { href: '#/settings', role: 'menuitem', onclick: () => closeWho() }, 'Profile and settings'),
    h('a', { href: '#/tv', role: 'menuitem', onclick: () => closeWho() }, 'TV view'),
    IN_APP ? h('a', { href: '/__app/profiles', role: 'menuitem' }, 'Switch profile') : null,
    IN_APP ? h('a', { href: '/__app/settings', role: 'menuitem' }, 'App settings') : null,
    h('button', { type: 'button', role: 'menuitem', onclick: logout }, 'Sign out'));
  const btn = h('button', { class: 'who', id: 'who', type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false', title: 'Your profile',
    onclick: (e) => { e.stopPropagation(); const open = menu.classList.toggle('hidden') === false; btn.setAttribute('aria-expanded', String(open)); } },
    h('span', { class: 'who-name' }, S.me.user), avatarEl(S.me.user, S.me.avatar, 30));
  slot.replaceChildren(btn, menu);
}
function closeWho() {
  const m = $('#who-menu'), b = $('#who');
  if (m) m.classList.add('hidden');
  if (b) b.setAttribute('aria-expanded', 'false');
}
document.addEventListener('click', (e) => { if (!e.target.closest || !e.target.closest('.who-wrap')) closeWho(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeWho(); });

// the poster art for a show or movie: the real picture when we have one, else the coloured card
function posterArt(g) {
  const withArt = g.eps.find((e) => e.poster);
  return withArt ? h('img', { class: 'art', loading: 'lazy', alt: '', src: '/api/poster/' + withArt.id }) : null;
}
const genresOf = (g) => [...new Set(g.eps.flatMap((e) => e.genres || []))];
// genres that earn a row even with a single title, so a lone horror film is not lost among comedies
const MAIN_GENRES = new Set(['Action', 'Adventure', 'Animation', 'Comedy', 'Crime', 'Documentary', 'Drama', 'Family', 'Fantasy', 'History', 'Horror', 'Music', 'Mystery', 'Romance', 'Sci-Fi', 'Sports', 'Thriller', 'War', 'Western']);

// A "⋯" button with a small menu under it. items: [{ label, run, danger }]
function moreMenu(items, label) {
  const menu = h('div', { class: 'pop-menu hidden', role: 'menu' }, items.map((i) => h('button', { type: 'button', role: 'menuitem', class: i.danger ? 'danger' : '',
    onclick: (e) => { e.stopPropagation(); menu.classList.add('hidden'); i.run(); } }, i.label)));
  const btn = h('button', { class: 'btn icon', type: 'button', 'aria-haspopup': 'menu', 'aria-label': label || 'More', title: label || 'More',
    onclick: (e) => { e.stopPropagation(); document.querySelectorAll('.pop-menu').forEach((m) => { if (m !== menu) m.classList.add('hidden'); }); menu.classList.toggle('hidden'); } }, '⋯');
  return h('div', { class: 'pop-wrap' }, btn, menu);
}
document.addEventListener('click', () => document.querySelectorAll('.pop-menu').forEach((m) => m.classList.add('hidden')));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') document.querySelectorAll('.pop-menu').forEach((m) => m.classList.add('hidden')); });

// Drag a row sideways with the mouse (touch screens and trackpads already scroll natively)
function enableDrag(rail) {
  let down = false, moved = false, sx = 0, sl = 0;
  rail.addEventListener('pointerdown', (e) => {
    if (e.pointerType !== 'mouse' || e.button !== 0) return;
    down = true; moved = false; sx = e.clientX; sl = rail.scrollLeft;
  });
  window.addEventListener('pointermove', (e) => {
    if (!down) return;
    const dx = e.clientX - sx;
    if (!moved && Math.abs(dx) > 5) { moved = true; rail.classList.add('dragging'); }
    if (moved) rail.scrollLeft = sl - dx;
  });
  const end = () => { down = false; rail.classList.remove('dragging'); };
  window.addEventListener('pointerup', end);
  window.addEventListener('pointercancel', end);
  // a drag must not count as a click on the poster under the pointer
  rail.addEventListener('click', (e) => { if (moved) { e.preventDefault(); e.stopPropagation(); moved = false; } }, true);
  rail.addEventListener('dragstart', (e) => e.preventDefault());
}

// One scrolling row of posters with a title; drag it or scroll it
function shelfRow(title, posters) {
  const rail = h('div', { class: 'rail', tabindex: '-1' }, posters);
  enableDrag(rail);
  return h('section', { class: 'shelf' },
    h('div', { class: 'shelf-title' }, title, h('small', null, posters.length)),
    rail);
}

// Genres, description and cast, when they have been looked up (or typed in)
function detailsBlock(it) {
  const d = it.details;
  const parts = [];
  if (it.genres && it.genres.length) parts.push(h('div', { class: 'tags' }, it.genres.map((g) => h('span', { class: 'tag' }, g))));
  if (d && d.overview) parts.push(h('p', { class: 'overview' }, d.overview));
  if (d && d.cast && d.cast.length) parts.push(h('div', { class: 'cast' }, h('span', { class: 'faint' }, 'Cast'),
    h('div', { class: 'cast-list' }, d.cast.slice(0, 10).map((c) => h('span', { class: 'cast-one' }, h('b', null, c.name), c.role ? h('small', null, c.role) : null)))));
  if (d && d.source) parts.push(h('p', { class: 'faint' }, 'Details from ' + d.source + (d.rating ? ' · rated ' + d.rating : '')));
  return parts.length ? h('div', { class: 'details' }, parts) : null;
}
const parseGenres = (txt) => txt.split(',').map((x) => x.trim()).filter(Boolean).slice(0, 8);

function posterEl(g, label, onopen, sel) {
  const first = g.eps[0];
  const present = g.eps.some((e) => e.local === 'present');
  const p = h('button', { class: 'poster' + (present ? '' : ' away') + (sel && sel.on ? ' picked' : ''), onclick: onopen, 'aria-label': (sel ? 'Select ' : 'Open ') + g.title, 'aria-pressed': sel ? String(!!sel.on) : null });
  p.style.setProperty('--h', hue(g.title));
  const art = posterArt(g);
  if (art) { p.classList.add('has-art'); art.addEventListener('error', () => { art.remove(); p.classList.remove('has-art'); }); }
  p.append(...[
    art,
    h('span', { class: 'kind' }, g.kind),
    sel ? h('span', { class: 'tick-box' }, sel.on ? '✓' : '') : g.eps.length > 1 ? h('span', { class: 'count' }, g.eps.length + ' eps') : null,
    present ? null : h('span', { class: 'away-tag' }, 'arriving from the mesh'),
    h('div', { class: 'cap' }, h('b', null, g.title), h('span', null, label || (g.key ? showSummary(g) : [g.year, fmtBytes(first.size)].filter(Boolean).join(' · ')))),
  ].filter(Boolean));
  return p;
}

// Apply a change to many items one after another (each is its own signed, synced edit).
async function patchMany(items, change, onprogress) {
  let ok = 0, bad = 0;
  for (let i = 0; i < items.length; i++) {
    onprogress && onprogress(i + 1, items.length);
    try { await api('/api/items/' + items[i].id, { method: 'PATCH', body: change(items[i], i) }); ok++; } catch { bad++; }
  }
  return { ok, bad };
}

function combineModal(groups, done) {
  const eps = groups.flatMap((g) => g.eps).sort(byEpisode);
  const title = h('input', { type: 'text', value: commonest(groups.map((g) => g.title)) });
  const kind = h('select', null, ['series', 'anime'].map((k) => h('option', { value: k, selected: k === (commonest(eps.map((e) => e.kind)) === 'anime' ? 'anime' : 'series') }, k)));
  const season = h('input', { type: 'number', min: 0, placeholder: 'Keep each episode\'s own' });
  const unnumbered = eps.some((e) => e.episode == null);
  const renum = h('input', { type: 'checkbox', checked: unnumbered });
  const status = h('p', { class: 'muted' });
  const go = h('button', { class: 'btn primary', onclick: async () => {
    if (!title.value.trim()) return toast('Give the series a title', 'bad');
    go.disabled = true;
    const forced = season.value === '' ? null : parseInt(season.value, 10);
    const counters = new Map();
    const plan = eps.map((e) => {
      const s = forced != null ? forced : e.season != null ? e.season : (renum.checked || e.episode != null) ? 1 : null;
      let n = e.episode;
      if (renum.checked) { const k = String(s); counters.set(k, (counters.get(k) || 0) + 1); n = counters.get(k); }
      return { id: e.id, season: s, episode: n, year: e.year };
    });
    const byId = new Map(plan.map((p) => [p.id, p]));
    const r = await patchMany(eps, (e) => ({ title: title.value.trim(), kind: kind.value, year: byId.get(e.id).year, season: byId.get(e.id).season, episode: byId.get(e.id).episode }),
      (i, n) => { status.textContent = 'Saving ' + i + ' of ' + n + '…'; });
    close();
    toast(r.bad ? r.ok + ' updated, ' + r.bad + ' failed' : 'Combined ' + r.ok + ' episodes into "' + title.value.trim() + '". Your other nodes get the change too.', r.bad ? 'bad' : 'ok');
    done();
  } }, 'Combine');
  const close = modal('Combine into one series', h('div', null,
    h('p', { class: 'muted' }, eps.length + ' items will become one series. Your other nodes see the same change.'),
    h('div', { class: 'grid-fields' },
      field('Series title', title), field('Type', kind),
      field('Put everything in season', season, 'Leave empty if the episodes already know their season'),
      h('label', { class: 'field check' }, renum, h('span', null, 'Number the episodes in order'), h('small', null, unnumbered ? 'Some have no episode number, so this is recommended.' : 'Only needed if the numbers are wrong.'))),
    status, h('div', { class: 'row' }, go)));
}

async function viewLibrary(el) {
  // coming back from a show or film keeps the search, the filter and the scroll position; opening Library afresh starts clean
  const back = S.lib.keep; S.lib.keep = false;
  if (!back) { S.lib.q = ''; S.lib.kind = ''; S.lib.scroll = 0; }
  let kind = S.lib.kind, q = S.lib.q;
  let organizing = false;
  const picked = new Set();
  let shown = [];
  const list = h('div');
  const search = h('input', { type: 'search', placeholder: 'Search your library', 'aria-label': 'Search', class: 'grow', value: q });
  const pills = h('div', { class: 'pills', role: 'group', 'aria-label': 'Filter' });
  const bar = h('div', { class: 'organize-bar hidden' });
  const canEdit = RANK[S.me.role] >= RANK.contributor;
  const orgBtn = canEdit ? h('button', { class: 'btn', onclick: () => { organizing = !organizing; picked.clear(); drawBar(); draw(shown); } }, 'Organize') : null;
  const head = h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Library'), h('p', null, 'Everything your node holds, decrypted only while you are signed in.')), h('div', { class: 'row' }, search, orgBtn));
  el.replaceChildren(head, pills, bar, list);

  const drawBar = () => {
    orgBtn && (orgBtn.textContent = organizing ? 'Done' : 'Organize');
    bar.classList.toggle('hidden', !organizing);
    if (!organizing) return bar.replaceChildren();
    const chosen = groupItems(shown).filter((g) => picked.has(g.id));
    bar.replaceChildren(
      h('span', null, picked.size ? picked.size + ' selected' : 'Pick the posters that belong to one show, then combine them.'),
      h('button', { class: 'btn primary small', disabled: chosen.length < 1, onclick: () => combineModal(chosen, () => { picked.clear(); organizing = false; drawBar(); load(); }) }, 'Combine into one series…'),
      h('button', { class: 'btn ghost small', disabled: !picked.size, onclick: () => { picked.clear(); drawBar(); draw(shown); } }, 'Clear'));
  };

  const draw = (items) => {
    shown = items;
    if (!items.length) {
      list.replaceChildren(h('div', { class: 'empty', style: null }, h('strong', null, q || kind ? 'Nothing matches' : 'The shelves are empty'),
        q || kind ? 'Try a different search.' : canEdit ? 'Add something from the Add tab, or wait for your other nodes to sync.' : 'Nothing has been added yet.'));
      return;
    }
    const frag = [];
    const resume = [];
    const seen = new Set();
    for (const i of items) {
      if (!(i.pos > 30 && i.local === 'present')) continue;
      const k = i.group || i.id;
      if (seen.has(k)) continue;
      seen.add(k); resume.push(i);
    }
    if (resume.length && !q && !kind && !organizing) {
      frag.push(shelfRow('Continue watching', resume.slice(0, 12).map((i) => posterEl({ title: i.title, kind: i.kind, year: i.year, eps: [i] }, [epLabel(i), 'resume at ' + fmtTime(i.pos)].filter(Boolean).join(' · '), () => { location.hash = '#/watch/' + i.id; }))));
    }
    const groups = groupItems(items);
    const open = (g) => (organizing
      ? posterEl(g, null, () => { picked.has(g.id) ? picked.delete(g.id) : picked.add(g.id); drawBar(); draw(shown); }, { on: picked.has(g.id) })
      : posterEl(g, null, () => { if (g.key) location.hash = '#/show/' + encodeURIComponent(g.key); else openMovie(g); }));
    // searching or organizing: one flat, wrapping grid per type, so everything is in view
    if (q || organizing) {
      for (const [k, title] of [['movie', 'Movies'], ['series', 'Series'], ['anime', 'Anime']]) {
        const gs = groups.filter((g) => g.kind === k);
        if (!gs.length) continue;
        frag.push(h('div', { class: 'shelf-title' }, title, h('small', null, gs.length)));
        frag.push(h('div', { class: 'grid' }, gs.map(open)));
      }
      list.replaceChildren(...frag);
      return;
    }
    // otherwise: horizontally scrolling rows, the way streaming apps do it
    const rows = [];
    const newest = [...groups].sort((a, b) => Math.max(...b.eps.map((e) => e.added_at || 0)) - Math.max(...a.eps.map((e) => e.added_at || 0)));
    if (groups.length >= 8) rows.push(['Recently added', newest.slice(0, 20)]);
    // Each title sits in ONE row: its main genre (the first the sources list), or "Anime" when every type is shown.
    // Anime has its own row in the mixed view; filter to Anime to see it split by genre.
    const mainOf = (g) => {
      if (g.kind === 'anime' && !kind) return 'Anime';
      const all = genresOf(g);
      return all.find((x) => MAIN_GENRES.has(x)) || all[0] || null;
    };
    const byGenre = new Map();
    for (const g of groups) { const m = mainOf(g); if (!m) continue; if (!byGenre.has(m)) byGenre.set(m, []); byGenre.get(m).push(g); }
    // the familiar genres always get a row; odd ones need two titles so the page does not fill with single-poster rows
    const placed = new Set();
    const ranked = [...byGenre.entries()].filter(([gen, gs]) => gen === 'Anime' || MAIN_GENRES.has(gen) || gs.length >= 2)
      .sort((a, b) => (a[0] === 'Anime') - (b[0] === 'Anime') || b[1].length - a[1].length || a[0].localeCompare(b[0]));
    ranked.slice(0, 16).forEach(([gen, gs]) => { rows.push([gen, gs]); gs.forEach((g) => placed.add(g)); });
    // whatever is not in a genre row stays findable under its type
    for (const [k, title] of [['movie', 'Movies'], ['series', 'Series'], ['anime', 'Anime']]) {
      const gs = groups.filter((g) => g.kind === k && !placed.has(g));
      if (gs.length) rows.push([rows.length ? 'More ' + title.toLowerCase() : title, gs]);
    }
    for (const [title, gs] of rows) frag.push(shelfRow(title, gs.map(open)));
    list.replaceChildren(...frag);
  };
  const load = async () => {
    const d = await api('/api/library?kind=' + encodeURIComponent(kind) + '&q=' + encodeURIComponent(q));
    draw(d.items);
    if (organizing) drawBar();
  };
  const setPills = () => pills.replaceChildren(...[['', 'All'], ['movie', 'Movies'], ['series', 'Series'], ['anime', 'Anime']].map(([k, label]) =>
    h('button', { class: 'pill' + (k === kind ? ' on' : ''), onclick: () => { kind = k; S.lib.kind = k; setPills(); load(); } }, label)));
  setPills();
  let t;
  search.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { q = search.value.trim(); S.lib.q = q; load(); }, 200); });
  await load();
  if (back && S.lib.scroll) { window.scrollTo(0, S.lib.scroll); requestAnimationFrame(() => window.scrollTo(0, S.lib.scroll)); }
  poll(() => { if (!organizing) load().catch(() => {}); }, 15000);
}

// One page per show: pick a season, pick an episode, or just continue.
async function viewShow(el, rawKey) {
  const key = decodeURIComponent(rawKey || '');
  const canEdit = RANK[S.me.role] >= RANK.contributor;
  let bucketId = null;
  let manage = false;
  let detail = null;
  const body = h('div');
  el.replaceChildren(h('div', { class: 'row' }, h('a', { class: 'btn small ghost', href: '#/library' }, '← Library')), body);

  const draw = async () => {
    const d = await api('/api/library');
    const eps = d.items.filter((i) => i.group === key);
    if (!eps.length) return body.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'Nothing here any more'), 'This show has no episodes left. ', h('a', { href: '#/library' }, 'Back to the library')));
    const g = finishGroup({ key, eps });
    try { detail = (await api('/api/items/' + g.eps[0].id, { quiet: true })).item; } catch { /* details are optional */ }
    const seasons = [...new Set(g.eps.map(seasonOf))].sort((a, b) => a - b);
    const present = g.eps.filter((e) => e.local === 'present');
    const started = present.filter((e) => e.pos > 30);
    const cont = started.length ? started[started.length - 1] : null;
    const label = (s) => (s === 0 ? 'Extras' : 'Season ' + s);
    const total = g.eps.reduce((a, e) => a + e.size, 0);

    const playBtn = present.length
      ? h('a', { class: 'btn primary', href: '#/watch/' + (cont || present[0]).id }, cont ? 'Continue ' + (epLabel(cont) || 'watching') + ' · ' + fmtTime(cont.pos) : 'Play ' + (epLabel(present[0]) || 'from the start'))
      : h('button', { class: 'btn primary', disabled: true }, 'Arriving from the mesh');

    const heroActions = h('div', { class: 'row' });
    const hero = h('div', { class: 'show-hero' },
      (() => {
        const a = h('div', { class: 'show-art' }, h('span', null, g.title.slice(0, 1).toUpperCase()));
        a.style.setProperty('--h', hue(g.title));
        if (detail && detail.poster) { const im = h('img', { src: '/api/poster/' + g.eps[0].id, alt: '' }); im.addEventListener('error', () => im.remove()); a.append(im); }
        return a;
      })(),
      h('div', { class: 'show-info' },
        h('div', { class: 'faint kindline' }, g.kind),
        h('h1', null, g.title),
        h('p', { class: 'muted' }, [g.year, showSummary(g), fmtBytes(total), present.length < g.eps.length ? present.length + ' on this node' : null].filter(Boolean).join(' · ')),
        heroActions,
        detail ? detailsBlock(detail) : null));

    // Seasons, or (for shows numbered straight through, like most anime) blocks of 25 episodes
    const buckets = seasons.length > 1
      ? seasons.map((sn) => ({ id: 's' + sn, label: label(sn), eps: g.eps.filter((e) => seasonOf(e) === sn) }))
      : g.eps.length > 30
        ? Array.from({ length: Math.ceil(g.eps.length / 25) }, (_, n) => {
          const part = g.eps.slice(n * 25, n * 25 + 25);
          const first = part[0].episode != null ? part[0].episode : n * 25 + 1;
          const last = part[part.length - 1].episode != null ? part[part.length - 1].episode : n * 25 + part.length;
          return { id: 'c' + n, label: 'Episodes ' + first + '–' + last, eps: part };
        })
        : [{ id: 'all', label: '', eps: g.eps }];
    const inCont = cont ? buckets.find((b) => b.eps.includes(cont)) : null;
    if (!bucketId || !buckets.some((b) => b.id === bucketId)) bucketId = (inCont || buckets[0]).id;
    const bucket = buckets.find((b) => b.id === bucketId);

    const picker = buckets.length > 1
      ? h('select', { class: 'season-select', 'aria-label': 'Season', onchange: (e) => { bucketId = e.target.value; draw(); } },
        buckets.map((b) => h('option', { value: b.id, selected: b.id === bucketId }, b.label + ' (' + b.eps.length + ')')))
      : null;

    const rowFor = (it) => {
      const playable = it.local === 'present';
      const name = it.episode != null ? 'Episode ' + it.episode + (it.ep_title ? ': ' + it.ep_title : '') : (it.ep_title || it.title);
      const state = playable ? null : it.local === 'syncing' ? 'syncing' : it.local === 'assembling' ? 'waiting for unlock' : 'not on this node yet';
      const sub = [it.season != null && seasons.length > 1 ? 'Season ' + it.season : null, fmtBytes(it.size), state].filter(Boolean).join(' · ');
      const go = () => { if (playable) location.hash = '#/watch/' + it.id; };
      const row = h('div', { class: 'ep2' + (playable ? '' : ' away') + (manage ? ' managing' : ''), tabindex: playable && !manage ? '0' : null, role: manage ? null : 'link',
        onclick: manage ? null : go, onkeydown: manage ? null : (e) => { if (e.key === 'Enter') go(); } },
        playable ? (() => { const im = h('img', { class: 'ep2-thumb', loading: 'lazy', alt: '', src: '/api/frame/' + it.id }); im.addEventListener('error', () => im.replaceWith(h('span', { class: 'ep2-num' }, it.episode != null ? it.episode : '▶'))); return im; })() : h('span', { class: 'ep2-num' }, it.episode != null ? it.episode : '▶'),
        h('span', { class: 'ep2-main' }, h('b', null, name), h('small', null, sub)),
        it.pos > 30 && playable ? h('span', { class: 'ep2-resume' }, 'Resume ' + fmtTime(it.pos)) : null,
        manage ? h('button', { class: 'btn small ghost', onclick: () => editItem(it, draw) }, 'Edit') : null,
        manage ? h('button', { class: 'btn small danger', onclick: async () => { if (confirm('Move ' + g.title + ' ' + (epLabel(it) || '') + ' to the trash? This syncs to your other nodes.')) { if (await act(() => api('/api/items/' + it.id, { method: 'DELETE' }), 'Moved to trash')) draw(); } } }, 'Delete') : null);
      return row;
    };

    const menu = canEdit ? moreMenu([
      { label: 'Edit title, type and genres', run: () => renameShow(g) },
      { label: manage ? 'Done editing episodes' : 'Edit or delete episodes', run: () => { manage = !manage; draw(); } },
      { label: 'Move the whole show to the trash', danger: true, run: async () => {
        if (!confirm('Move all ' + g.eps.length + ' episodes of ' + g.title + ' to the trash? This syncs to your other nodes.')) return;
        let bad = 0;
        for (const e of g.eps) { try { await api('/api/items/' + e.id, { method: 'DELETE' }); } catch { bad++; } }
        toast(bad ? 'Some episodes could not be moved' : 'Moved to trash', bad ? 'bad' : 'ok');
        location.hash = '#/library';
      } },
    ], 'Edit or delete') : null;
    heroActions.replaceChildren(playBtn, menu);

    body.replaceChildren(hero, h('div', { class: 'ep-head' }, h('h2', null, buckets.length > 1 || g.eps.length > 1 ? 'Episodes' : 'Watch'), picker, manage ? h('span', { class: 'faint' }, 'Editing: pick Edit or Delete on an episode, then choose Done editing in the ⋯ menu') : null),
      h('div', { class: 'eps2' }, bucket.eps.map(rowFor)));
  };

  const renameShow = (g) => {
    const title = h('input', { type: 'text', value: g.title });
    const kind = h('select', null, ['series', 'anime'].map((k) => h('option', { value: k, selected: k === g.kind }, k)));
    const status = h('p', { class: 'muted' });
    const genres = h('input', { type: 'text', value: (detail && detail.genres || []).join(', '), placeholder: 'Comedy, Drama' });
    const go = h('button', { class: 'btn primary', onclick: async () => {
      if (!title.value.trim()) return;
      go.disabled = true;
      const r = await patchMany(g.eps, (e) => ({ title: title.value.trim(), kind: kind.value, year: e.year, season: e.season, episode: e.episode }), (i, n) => { status.textContent = 'Saving ' + i + ' of ' + n + '…'; });
      if (genres.value.trim() !== (detail && detail.genres || []).join(', ')) {
        for (const e of g.eps) { try { await api('/api/items/' + e.id + '/genres', { method: 'PUT', body: { genres: parseGenres(genres.value) } }); } catch { /* shown below */ } }
      }
      close();
      toast(r.bad ? r.ok + ' updated, ' + r.bad + ' failed' : 'Updated ' + r.ok + ' episodes', r.bad ? 'bad' : 'ok');
      // the show may now live under a new key
      const nk = (await api('/api/library')).items.find((i) => i.id === g.eps[0].id);
      if (nk && nk.group && nk.group !== key) location.hash = '#/show/' + encodeURIComponent(nk.group); else draw();
    } }, 'Save for all ' + g.eps.length + ' episodes');
    const close = modal('Rename, type or genres', h('div', null, h('div', { class: 'grid-fields' }, field('Title', title), field('Type', kind), field('Genres', genres, 'Comma separated. Used for the rows in the Library. Only on this node.')), status, h('div', { class: 'row' }, go)));
  };

  await draw();
  poll(() => draw().catch(() => {}), 20000);
}

function openMovie(g) {
  const e = g.eps[0];
  if (e.local === 'present') location.hash = '#/watch/' + e.id;
  else toast('This one is still arriving from the mesh.');
}

function editItem(it, done) {
  const title = h('input', { type: 'text', value: it.title });
  const kind = h('select', null, ['movie', 'series', 'anime'].map((k) => h('option', { value: k, selected: k === it.kind }, k)));
  const num = (v) => h('input', { type: 'number', value: v == null ? '' : v });
  const year = num(it.year), season = num(it.season), episode = num(it.episode);
  const genres = h('input', { type: 'text', value: (it.genres || []).join(', '), placeholder: 'Comedy, Horror' });
  const n = (i) => (i.value === '' ? null : parseInt(i.value, 10));
  const close = modal('Edit details', h('div', { class: 'grid-fields' },
    field('Title', title), field('Kind', kind), field('Year', year), field('Season', season), field('Episode', episode), field('Genres', genres, 'Comma separated. Only on this node.'),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => {
      if (await act(async () => {
        await api('/api/items/' + it.id, { method: 'PATCH', body: { title: title.value, kind: kind.value, year: n(year), season: n(season), episode: n(episode) } });
        if (genres.value.trim() !== (it.genres || []).join(', ')) await api('/api/items/' + it.id + '/genres', { method: 'PUT', body: { genres: parseGenres(genres.value) } });
      }, 'Saved and shared with your nodes')) { close(); done(); }
    } }, 'Save'))));
}

// ------------------------------------------------------------------ watch
// A plain video element that switches to a converted stream by itself when the browser cannot show the picture
// (MKV with HEVC, 10-bit, old formats ...). `url` is the stream address without a query.
function playerWithFallback(url, attrs) {
  const v = h('video', { controls: true, playsinline: true, ...attrs, src: url });
  let tried = false;
  const convert = () => { if (tried) return; tried = true; toast('This format needs converting. Switching to a compatible stream…', 'ok'); v.src = url + '?mode=transcode&q=medium&codec=' + browserCodec(); v.play().catch(() => {}); };
  v.addEventListener('error', convert);
  v.addEventListener('loadedmetadata', () => { if (v.videoWidth === 0) convert(); });
  return v;
}

// Can this browser show AV1? Conversions use AV1 when it can (smaller, same sharpness) and H.264 when not.
function browserCodec() {
  try { return document.createElement('video').canPlayType('video/mp4; codecs="av01.0.05M.08"') ? 'av1' : 'h264'; } catch { return 'h264'; }
}

async function viewWatch(el, id) {
  const d = await api('/api/items/' + encodeURIComponent(id));
  const it = d.item;
  let offset = 0;
  const video = h('video', { controls: true, autoplay: true, playsinline: true, preload: 'auto' });
  // How this video reaches the browser: as stored ('direct'), same picture in a friendlier wrapper ('remux'),
  // or re-encoded ('transcode') at the quality chosen here or in Settings. The node looks inside the file to decide.
  let pb = { mode: 'direct', duration: 0, reason: '' };
  let audioOk = true;
  let nodeQ = 'medium';
  let qualities = [];
  try {
    const [p, q] = await Promise.all([api('/api/items/' + encodeURIComponent(id) + '/playback', { quiet: true }), api('/api/playback', { quiet: true })]);
    pb = p.playback; audioOk = p.audio_ok; nodeQ = p.quality; qualities = q.qualities;
  } catch { /* play it as stored and let the browser say */ }
  // 'auto' (the file as stored) or a quality id. Away from home the picture travels over Tor, which carries far less than a home
  // connection, so the smooth 480p version is the default there; the picker below lets you ask for more.
  let choice = S.playQ || (fastLink() ? 'auto' : 'low');
  let forced = null; // set when the browser could not play it as stored
  const modeNow = () => (forced || (choice !== 'auto' ? 'transcode' : pb.mode));
  const converted = () => modeNow() !== 'direct';
  const qNow = () => (choice !== 'auto' ? choice : nodeQ);
  const src = (start) => {
    const t = Math.floor(start || 0);
    const m = modeNow();
    if (m === 'remux') return '/api/stream/' + id + '?mode=remux&audio_ok=' + audioOk + '&start=' + t;
    if (m === 'transcode') return '/api/stream/' + id + '?mode=transcode&q=' + qNow() + '&codec=' + browserCodec() + '&start=' + t;
    return '/api/stream/' + id;
  };
  const position = () => offset + (video.currentTime || 0);
  let lastSaved = 0;
  const save = (force) => {
    const p = position();
    if (!force && Math.abs(p - lastSaved) < 8) return;
    lastSaved = p;
    api('/api/progress/' + id, { method: 'PUT', body: { pos: p }, quiet: true }).catch(() => {});
  };
  const seek = h('input', { type: 'range', min: 0, max: Math.max(1, Math.floor(pb.duration || 0)), step: 1, value: 0, class: 'seekbar', 'aria-label': 'Position' });
  const seekRow = h('div', { class: 'row seekrow' }, h('span', { class: 'faint', id: 'seek-now' }, '0:00'), seek, h('span', { class: 'faint' }, fmtTime(pb.duration || 0)));
  let dragging = false;
  seek.addEventListener('input', () => { dragging = true; $('#seek-now', seekRow).textContent = fmtTime(+seek.value); });
  seek.addEventListener('change', () => { dragging = false; load(+seek.value); });
  const info = h('p', { class: 'faint' });
  const drawInfo = () => {
    seekRow.classList.toggle('hidden', !(converted() && pb.duration > 0));
    const m = modeNow();
    info.textContent = m === 'direct' ? 'Playing the file as it is.'
      : m === 'remux' ? 'Playing with the same picture, re-wrapped for your browser' + (pb.reason ? ' (' + pb.reason + ')' : '') + '. Use the bar or the jump buttons to move around.'
      : 'Converted on the node to ' + ((qualities.find((x) => x.id === qNow()) || {}).label || qNow()) + (choice === 'auto' && pb.reason ? ' because ' + pb.reason : '') + '. Use the bar or the jump buttons to move around.';
    skip.classList.toggle('hidden', !converted());
  };
  const load = (start) => {
    offset = converted() ? start || 0 : 0;
    video.src = src(start);
    if (!converted() && start > 5) video.addEventListener('loadedmetadata', () => { if (start < (video.duration || 1e9) - 20) video.currentTime = start; }, { once: true });
    video.play().catch(() => {});
    drawInfo();
  };
  // a file whose picture the browser cannot show still has sound: switch to a converted stream by itself
  const fallBack = (why) => {
    if (modeNow() === 'transcode') return toast('Playback failed. The node may be locked or busy; try a lower quality.', 'bad');
    const p = position();
    forced = modeNow() === 'direct' ? 'remux' : 'transcode';
    if (why === 'novideo') forced = 'transcode';
    toast('This format needs converting. Switching to a compatible stream…', 'ok');
    load(p);
  };
  video.addEventListener('loadedmetadata', () => { if (modeNow() !== 'transcode' && video.videoWidth === 0 && pb.vcodec !== '') fallBack('novideo'); });
  video.addEventListener('timeupdate', () => {
    if (!video.paused) save(false);
    if (!dragging && converted()) { seek.value = Math.floor(position()); $('#seek-now', seekRow).textContent = fmtTime(position()); }
  });
  video.addEventListener('pause', () => save(true));
  video.addEventListener('ended', () => save(true));
  video.addEventListener('error', () => fallBack('error'));

  const qSel = h('select', { class: 'small', 'aria-label': 'Quality', onchange: (e) => { const p = position(); choice = e.target.value; S.playQ = choice; forced = null; load(p); } },
    h('option', { value: 'auto', selected: choice === 'auto' }, fastLink() ? 'Original (automatic)' : 'Original (may stall over Tor)'),
    qualities.map((q) => h('option', { value: q.id, selected: choice === q.id, title: q.detail }, 'Convert: ' + q.label)));
  const jump = (dt) => h('button', { class: 'btn small ghost', onclick: () => load(Math.max(0, position() + dt)) }, (dt > 0 ? '+' : '') + dt + 's');
  const skip = h('div', { class: 'row hidden' }, h('span', { class: 'muted' }, 'Jump:'), jump(-60), jump(-10), jump(10), jump(60));

  const next = h('div', { class: 'nextep' });
  const canEditHere = RANK[S.me.role] >= RANK.contributor;
  const watchMenu = canEditHere ? moreMenu([
    { label: 'Edit details', run: () => editItem(it, () => route()) },
    { label: 'Move to the trash', danger: true, run: async () => {
      if (!confirm('Move "' + it.title + '" ' + (epLabel(it) || '') + ' to the trash? This syncs to your other nodes.')) return;
      if (await act(() => api('/api/items/' + it.id, { method: 'DELETE' }), 'Moved to trash')) location.hash = it.group ? '#/show/' + encodeURIComponent(it.group) : '#/library';
    } },
  ], 'Edit or delete') : null;
  el.replaceChildren(
    h('div', { class: 'row', style: null }, h('a', { class: 'btn small ghost', href: it.group ? '#/show/' + encodeURIComponent(it.group) : '#/library' }, it.group ? '← All episodes' : '← Library')),
    h('div', { class: 'stage' }, video),
    next,
    h('div', { class: 'watch-meta' },
      h('div', null, h('h2', null, it.title + (epLabel(it) ? ' · ' + epLabel(it) : '')), it.ep_title ? h('p', { class: 'ep-name' }, (it.episode != null ? 'Episode ' + it.episode + ': ' : '') + it.ep_title) : null, h('p', { class: 'muted' }, [it.kind, it.year, fmtBytes(it.size)].filter(Boolean).join(' · '))),
      h('div', { class: 'row' }, qSel, skip, watchMenu)),
    seekRow,
    info,
    detailsBlock(it));
  load(d.pos);
  // Tell the node someone is watching, so rest mode never starts in the middle of a film: every 45 seconds while it
  // plays, and while it is paused for up to an hour (a short break is not "nobody is here").
  let pausedSince = 0;
  video.addEventListener('pause', () => { pausedSince = Date.now(); });
  video.addEventListener('play', () => { pausedSince = 0; });
  S.timers.push(setInterval(() => {
    if (!document.body.contains(video)) return;
    if (!video.paused || (pausedSince && Date.now() - pausedSince < 3600000)) api('/api/presence', { method: 'POST', body: {}, quiet: true }).catch(() => {});
  }, 45000));
  window.addEventListener('beforeunload', () => save(true), { once: true });
  S.leave = () => { save(true); video.pause(); video.removeAttribute('src'); video.load(); };

  if (it.kind !== 'movie' && it.group) {
    const lib = await api('/api/library');
    const eps = lib.items.filter((i) => i.group === it.group && i.local === 'present').sort(byEpisode);
    const idx = eps.findIndex((i) => i.id === id);
    if (idx >= 0 && eps[idx + 1]) next.replaceChildren(h('a', { class: 'btn primary', href: '#/watch/' + eps[idx + 1].id }, 'Next episode: ' + [epLabel(eps[idx + 1]) || 'next episode', eps[idx + 1].ep_title].filter(Boolean).join(' · ') + ' →'));
  }
}
window.addEventListener('hashchange', () => { if (S.leave) { const f = S.leave; S.leave = null; f(); } });

// ------------------------------------------------------------------ add: search, download, upload
async function viewAdd(el) {
  const prov = await api('/api/acquire/providers');
  const results = h('div');
  const dls = h('div');
  const q = h('input', { type: 'search', placeholder: 'A title, or paste a link to a video', class: 'grow', 'aria-label': 'Title to search' });
  const sel = h('select', { 'aria-label': 'Source', style: null }, h('option', { value: '' }, 'All sources'), prov.providers.map((p) => h('option', { value: p.id }, p.label)));
  const kindSel = h('select', { 'aria-label': 'What is this?', title: 'Tell Syphon what you are adding. Auto works it out from the name.' },
    h('option', { value: '' }, 'Auto-detect type'), h('option', { value: 'movie' }, 'Movie'), h('option', { value: 'series' }, 'TV series'), h('option', { value: 'anime' }, 'Anime'));
  const go = h('button', { class: 'btn primary', type: 'submit' }, 'Search');
  const form = h('form', { class: 'row', onsubmit: async (e) => {
    e.preventDefault();
    if (!q.value.trim()) return;
    go.disabled = true; go.textContent = 'Searching…';
    results.replaceChildren(h('p', { class: 'muted' }, 'Searching ' + (prov.route === 'tor' ? 'through Tor (this can take a while)…' : '…')));
    try {
      const d = await api('/api/acquire/search?q=' + encodeURIComponent(q.value) + '&provider=' + encodeURIComponent(sel.value));
      if (!d.results.length) return results.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'No results'), 'Try other words, or another source.'));
      results.replaceChildren(h('div', { class: 'eps' }, d.results.map((r) => h('div', { class: 'ep' },
        h('span', { class: 'num' }, r.year || '—'),
        h('span', { class: 'meta' }, h('b', { style: null }, r.title), ' ', h('span', { class: 'faint' }, [r.note, r.size ? fmtBytes(r.size) : null].filter(Boolean).join(' · '))),
        h('button', { class: 'btn small primary', onclick: async (ev) => {
          ev.target.disabled = true;
          if (await act(() => api('/api/acquire/queue', { method: 'POST', body: { provider: r.provider, url: r.url, title: r.title, kind: kindSel.value || r.kind || '' } }), 'Queued. It will land in Review when done.')) ev.target.textContent = 'Queued';
          else ev.target.disabled = false;
        } }, 'Download')))));
    } catch (ex) {
      results.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'Search failed'), ex.message));
    } finally { go.disabled = false; go.textContent = 'Search'; }
  } }, q, sel, go);
  const typeRow = h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Adding a:'), kindSel, h('span', { class: 'faint' }, 'Anime gets filed as anime, not as a movie. You can still fix it in Review.'));

  const search = prov.providers.length
    ? h('div', null, form, typeRow, h('div', { class: 'note' }, (prov.route === 'tor' ? 'Searches and downloads go through Tor, so the sites you use cannot see your address. ' : 'Searches and downloads leave directly, not through Tor. ') + 'Your own Plex or Jellyfin on the home network is always reached directly. Everything waits in the isolated Review area until you approve it.'), results)
    : h('div', { class: 'empty' }, h('strong', null, 'No sources configured'), 'Add a Plex or Jellyfin server under Settings, or paste a direct link to a video.');

  // upload
  const files = h('div', { class: 'uploads' });
  const input = h('input', { type: 'file', accept: 'video/*,.mkv,.avi,.ts,.m2ts', multiple: true, class: 'hidden' });
  const drop = h('div', { class: 'drop', tabindex: '0', role: 'button', 'aria-label': 'Choose video files to upload', onclick: () => input.click(), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } } },
    h('strong', null, 'Drop videos here, or click to choose'), h('span', null, 'Videos only. Large files upload in pieces and pick up where they left off if the connection drops. They are encrypted as they arrive and scanned in the background.'));
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  // many files at once: one summary and a collapsible list, two uploads at a time
  const q2 = [];
  let running = 0, nTotal = 0, nDone = 0, nFailed = 0, bytesAll = 0, bytesDone = 0;
  const sumText = h('b'), sumSub = h('span', { class: 'muted' }), sumBar = h('i');
  sumBar.style.width = '0%';
  const rows = h('div', { class: 'stack' });
  const det = h('details', { class: 'group-details' }, h('summary', null, 'Show each file'), rows);
  const summary = h('div', { class: 'panel hidden' }, h('div', { class: 'row spread' }, sumText, sumSub), h('div', { class: 'progress' }, sumBar), det);
  files.append(summary);
  const refresh = (live) => {
    summary.classList.remove('hidden');
    sumText.textContent = nDone + nFailed >= nTotal ? 'Uploaded ' + nDone + ' of ' + nTotal + ' files' : 'Uploading ' + nTotal + ' file' + (nTotal === 1 ? '' : 's');
    sumSub.textContent = nFailed ? nDone + ' done · ' + nFailed + ' failed' : nDone + ' done';
    sumBar.style.width = (bytesAll ? Math.min(100, 100 * (bytesDone + live) / bytesAll) : 0).toFixed(1) + '%';
    if (nTotal <= 3) det.open = true;
  };
  let parallel = 2; // how many files go at once: the node says what it can take (more on a dedicated machine)
  api('/api/perf', { quiet: true }).then((d) => { if (d && d.upload_parallel) parallel = d.upload_parallel; }).catch(() => {});
  const pump = () => {
    while (running < parallel && q2.length) { running++; send(q2.shift()); }
  };
  const live = new Map();
  const liveSum = () => [...live.values()].reduce((a, b) => a + b, 0);
  const CHUNK = 8 * 1024 * 1024;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  // one request carrying one slice of the file; resolves with {status, data}
  const putSlice = (url, blob, onprog) => new Promise((res) => {
    const x = new XMLHttpRequest();
    x.open('PUT', url);
    x.setRequestHeader('x-requested-with', 'syphon');
    x.upload.onprogress = (e) => onprog(e.loaded);
    x.onload = () => { let d = {}; try { d = JSON.parse(x.responseText); } catch { /* ignore */ } res({ status: x.status, data: d }); };
    x.onerror = () => res({ status: 0, data: {} });
    x.ontimeout = () => res({ status: 0, data: {} });
    x.timeout = 120000;
    x.send(blob);
  });
  const send = async (f) => {
    const status = h('span', { class: 'muted' }, 'starting');
    rows.append(h('div', { class: 'row spread' }, h('span', null, f.name), status));
    let sid = null, off = 0, fails = 0, restarts = 0;
    const end = (ok, text, dup) => {
      live.delete(f); running--; bytesDone += f.size;
      if (ok) nDone++; else nFailed++;
      status.textContent = text;
      if (!ok) toast(text + ': ' + f.name, 'bad');
      refresh(liveSum());
      if (!q2.length && !running && nDone) toast(nTotal === 1 ? (dup ? f.name + ' is already in your library' : f.name + ' is waiting in Review') : nDone + ' files are waiting in Review, grouped by show', 'ok');
      pump();
    };
    // a dropped connection or a restarted node is not the end: wait, ask where the node got to, carry on
    for (;;) {
      try {
        if (!sid) {
          const st = await fetch('/api/upload/start?name=' + encodeURIComponent(f.name) + '&size=' + f.size + (kindSel.value ? '&kind=' + kindSel.value : ''),
            { method: 'POST', headers: { 'x-requested-with': 'syphon' }, credentials: 'same-origin' });
          const sd = await st.json().catch(() => ({}));
          if (st.status === 415 || st.status === 400) return end(false, sd.error || 'only videos can be added');
          if (!st.ok) throw new Error(sd.error || 'start failed');
          sid = sd.sid; off = 0;
        }
        while (off < f.size) {
          const slice = f.slice(off, Math.min(f.size, off + CHUNK));
          status.textContent = 'uploading';
          const r = await putSlice('/api/upload/' + sid + '?offset=' + off, slice, (n) => { live.set(f, off + n); refresh(liveSum()); });
          if (r.status === 415) return end(false, r.data.error || 'only videos can be added');
          if (r.status === 404 || r.status === 410) { sid = null; if (++restarts > 5) return end(false, 'the node lost this upload too many times'); throw new Error('restart'); }
          if (r.status === 409 && typeof r.data.received === 'number') { off = r.data.received; continue; }
          if (r.status !== 200) throw new Error(r.data.error || 'interrupted');
          const got = typeof r.data.received === 'number' ? r.data.received : off + slice.size;
          off = got; fails = 0;
          live.set(f, off); refresh(liveSum());
        }
        const fin = await fetch('/api/upload/' + sid + '/finish', { method: 'POST', headers: { 'x-requested-with': 'syphon' }, credentials: 'same-origin' });
        const d = await fin.json().catch(() => ({}));
        if (fin.status === 409 && sid) { const st = await fetch('/api/upload/' + sid, { credentials: 'same-origin' }).then((x) => x.json()).catch(() => null); if (st && typeof st.received === 'number') { off = st.received; continue; } }
        if (fin.ok) return end(true, d.restored ? 'brought back from the trash' : d.duplicate ? 'already known' : 'in Review. Scanning continues by itself', d.duplicate || d.restored);
        if (fin.status === 401 || fin.status === 403) return end(false, d.error || 'not allowed');
        throw new Error(d.error || 'finish failed');
      } catch (ex) {
        if (ex.message === 'restart') { await sleep(500); continue; }
        if (++fails > 40) return end(false, 'the connection kept dropping');
        const wait = Math.min(15000, 1000 * fails);
        status.textContent = 'connection dropped, trying again…';
        await sleep(wait);
        // find out how much the node already has
        if (sid) {
          try {
            const st = await fetch('/api/upload/' + sid, { credentials: 'same-origin' });
            if (st.status === 404) sid = null;
            else if (st.ok) { const d = await st.json(); if (typeof d.received === 'number') off = d.received; }
          } catch { /* still offline: loop again */ }
        }
      }
    }
  };
  const upload = (f) => { nTotal++; bytesAll += f.size; q2.push(f); refresh(liveSum()); pump(); };
  const VIDEO_EXT = /\.(mp4|m4v|mov|mkv|webm|avi|ts|m2ts|ogv|ogg|flv|mpg|mpeg|wmv)$/i;
  const take = (list) => {
    const all = Array.from(list), vids = all.filter((f) => VIDEO_EXT.test(f.name));
    if (vids.length < all.length) toast((all.length - vids.length) + ' file' + (all.length - vids.length === 1 ? ' was' : 's were') + ' skipped: Syphon only takes videos, it is not a file server.', 'bad');
    vids.forEach(upload);
  };
  input.addEventListener('change', () => { take(input.files); input.value = ''; });
  drop.addEventListener('drop', (e) => take(e.dataTransfer.files));

  const STATUS_TEXT = { queued: 'Waiting for a free slot', resolving: 'Starting', downloading: 'Downloading', retrying: 'Connection dropped, retrying', waiting: 'Paused until the node is ready',
    review: 'Waiting in Review', blocked: 'Blocked by the safety scan', approved: 'Added to the library', rejected: 'Rejected', failed: 'Failed', cancelled: 'Cancelled', duplicate: 'Already in your library' };
  const LIVE = ['queued', 'resolving', 'downloading', 'retrying', 'waiting'];
  let drawing = false;
  const drawDownloads = async () => {
    if (drawing) return;
    drawing = true;
    try {
      const d = await api('/api/downloads', { quiet: true });
      const redo = () => drawDownloads();
      if (!d.downloads.length) return dls.replaceChildren(h('p', { class: 'muted' }, 'No downloads yet.'));
      const finished = d.downloads.filter((x) => !LIVE.includes(x.status) && x.status !== 'review');
      dls.replaceChildren(
        finished.length ? h('div', { class: 'row' }, h('button', { class: 'btn small ghost', onclick: () => act(() => api('/api/downloads/clear', { method: 'POST' })).then(redo) }, 'Clear finished (' + finished.length + ')')) : null,
        h('table', { class: 'table' }, h('thead', null, h('tr', null, ['Title', 'Status', 'Progress', ''].map((t) => h('th', null, t)))),
          h('tbody', null, d.downloads.map((x) => {
            const done = ['review', 'approved', 'rejected', 'duplicate'].includes(x.status);
            const pct = x.total ? Math.min(100, (100 * x.got) / x.total) : done && x.status !== 'rejected' ? 100 : 0;
            const bar = h('i'); bar.style.width = pct + '%';
            const live = LIVE.includes(x.status);
            const btns = [];
            if (live) btns.push(h('button', { class: 'btn small danger', onclick: () => act(() => api('/api/downloads/' + x.id + '/cancel', { method: 'POST' }), 'Cancelled').then(redo) }, 'Cancel'));
            if (x.status === 'failed' || x.status === 'cancelled') btns.push(h('button', { class: 'btn small', onclick: () => act(() => api('/api/downloads/' + x.id + '/retry', { method: 'POST' }), 'Trying again').then(redo) }, 'Retry'));
            if (!live && x.status !== 'review') btns.push(h('button', { class: 'btn small ghost', title: 'Remove from this list', onclick: () => act(() => api('/api/downloads/' + x.id, { method: 'DELETE' })).then(redo) }, 'Remove'));
            return h('tr', null, h('td', null, x.title),
              h('td', null, h('span', { class: 'status ' + x.status }, STATUS_TEXT[x.status] || x.status), x.error ? h('div', { class: 'faint' }, x.error) : null),
              h('td', { width: '26%' }, done && x.status !== 'review' ? null : h('div', { class: 'progress' }, bar), h('span', { class: 'faint' }, x.got ? fmtBytes(x.got) + (x.total ? ' / ' + fmtBytes(x.total) : '') : '')),
              h('td', { class: 'actions' }, btns));
          }))));
    } finally { drawing = false; }
  };

  el.replaceChildren(
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Add'), h('p', null, 'Search a source, paste a link, or upload files. Nothing reaches the library until you approve it.'))),
    h('div', { class: 'grid-2' },
      h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Search and download')), search),
      h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Upload from this device')), drop, input, files)),
    h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Downloads')), dls));
  poll(() => drawDownloads().catch(() => {}), 2500);
}

// ------------------------------------------------------------------ review
const ENGINE_NAMES = { signatures: 'hidden-program signatures', structure: 'file structure', blocklist: 'known-bad list', ffprobe: 'ffprobe', decode: 'decoder test', clamav: 'ClamAV' };
function scanView(s) {
  if (!s) return h('p', { class: 'muted' }, 'Not scanned yet.');
  const finds = (s.findings || []).map((f) => h('div', { class: 'line' }, h('span', { class: 'tick ' + (f.level === 'block' ? 'no' : 'na') }, f.level === 'block' ? '✕' : '!'), h('span', null, h('b', null, f.level === 'block' ? 'Dangerous: ' : 'Suspicious: '), f.what)));
  const ran = (s.engines || []).length ? h('p', { class: 'faint' }, 'Checked ' + (s.scanned_bytes ? fmtBytes(s.scanned_bytes) + ' ' : '') + 'with: ' + s.engines.map((e) => ENGINE_NAMES[e] || e).join(', ') + (s.complete === false ? '. Some checks covered only part of the file.' : '.')) : null;
  const line = (ok, text) => h('div', { class: 'line' }, h('span', { class: 'tick ' + (ok === true ? 'ok' : ok === false ? 'no' : 'na') }, ok === true ? '✓' : ok === false ? '✕' : '–'), h('span', null, text));
  return h('div', { class: 'scan' },
    line(!!s.container, s.container ? 'Container looks like ' + s.container : 'Not a recognised video container'),
    line(s.probed ? true : null, s.probed ? 'Inspected by ffprobe (sandbox: ' + s.sandbox + ')' : 'ffprobe did not read it'),
    line(s.probed ? s.has_video : null, s.has_video ? 'Has a video stream' + (s.duration ? ', ' + fmtTime(s.duration) : '') : 'No video stream confirmed'),
    line(s.extension_ok, s.extension_ok ? 'Expected file extension' : 'Unusual file extension'),
    finds,
    s.notes && s.notes.length ? h('ul', { class: 'notes' }, s.notes.map((n) => h('li', null, n))) : null,
    ran);
}

async function viewReview(el) {
  const list = h('div');
  el.replaceChildren(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Review'),
    h('p', null, 'The isolated area. Every new file, whether uploaded, downloaded or sent by another node, is scanned and then waits here, kept apart from your library and your other nodes, until you approve it. Files that look like malware are blocked and cannot be approved.'))), list);
  let busy = false; // a bulk action is running: do not redraw under it
  const open = new Set(); // groups the owner has expanded stay open while the list refreshes

  // watch a file before deciding; it streams from the isolated copy on this node only
  const previewBox = (it) => {
    const box = h('div');
    box.append(h('button', { class: 'btn small', onclick: (ev) => {
      ev.target.remove();
      const v = playerWithFallback('/api/review/' + it.id + '/stream', { preload: 'metadata', class: 'preview' });
      v.addEventListener('error', () => box.append(h('p', { class: 'faint' }, 'This file would not play in the browser. You can still approve it, then use the low-quality mode when watching.')));
      box.append(v);
      v.play().catch(() => {});
    } }, 'Preview'));
    return box;
  };
  // fix how it is identified (title, type, season, episode) before it joins the library
  const editBox = (it, load) => {
    const title = h('input', { value: it.title, 'aria-label': 'Title' });
    const kind = h('select', { 'aria-label': 'Type' }, [['movie', 'Movie'], ['series', 'TV series'], ['anime', 'Anime']].map(([v, t]) => h('option', { value: v, selected: it.kind === v }, t)));
    const num = (v, label) => h('input', { type: 'number', min: '0', max: '9999', value: v == null ? '' : v, placeholder: label, 'aria-label': label, class: 'num-in' });
    const season = num(it.season, 'Season'), episode = num(it.episode, 'Episode'), year = num(it.year, 'Year');
    const genres = h('input', { value: (it.genres || []).join(', '), placeholder: 'Genres, e.g. Comedy', 'aria-label': 'Genres' });
    const n = (el) => (el.value === '' ? null : parseInt(el.value, 10));
    return h('details', { class: 'group-details' }, h('summary', null, 'Fix title, type or genres'),
      h('div', { class: 'row' }, title, kind, season, episode, year, genres,
        h('button', { class: 'btn small', onclick: () => act(() => api('/api/review/' + it.id, { method: 'PATCH', body: { title: title.value, kind: kind.value, season: n(season), episode: n(episode), year: n(year), genres: parseGenres(genres.value) } }), 'Saved').then(load) }, 'Save')));
  };

  const itemPanel = (it, load) => {
    const ok = it.scan && it.scan.ok;
    const hard = !!(it.scan && it.scan.hard);
    return h('section', { class: 'panel' + (hard ? ' danger-panel' : '') },
      h('div', { class: 'panel-head' },
        h('div', null, h('h2', null, it.title + (it.year ? ' (' + it.year + ')' : '') + (epLabel(it) ? ' · ' + epLabel(it) : '')),
          h('div', { class: 'faint' }, [it.filename, fmtBytes(it.size), 'from ' + (it.source || 'unknown'), it.catalog ? 'synced from a peer' : null].filter(Boolean).join(' · '))),
        h('span', { class: 'verdict ' + (ok ? 'ok' : 'no') }, hard ? 'Blocked: unsafe' : ok ? 'Scan passed' : it.scan ? 'Needs your attention' : 'Scanning')),
      hard ? h('p', { class: 'notice-text' }, it.local === 'blocked' || it.catalog ? 'This file arrived from another node and was stopped here. It was not added to your library and is not shared with anyone. Reject it, and consider checking the node it came from.' : 'This file looks like malware or hides a program. It cannot be approved. Reject it to delete it.') : it.local === 'blocked' ? h('p', { class: 'notice-text' }, 'This file arrived from another node and did not pass the safety scan, so it is being held here. Nothing was added to your library or passed on.') : null,
      scanView(it.scan),
      hard ? null : previewBox(it),
      editBox(it, load),
      hard ? h('div', { class: 'row' }, h('button', { class: 'btn danger', onclick: () => { if (confirm('Delete this file permanently?')) act(() => api('/api/review/' + it.id + '/reject', { method: 'POST' }), 'Deleted').then(load); } }, 'Reject and delete'),
        h('button', { class: 'btn ghost', onclick: () => act(() => api('/api/review/' + it.id + '/rescan', { method: 'POST' }), 'Scanned again').then(load) }, 'Scan again')) :
      h('div', { class: 'row' },
        h('button', { class: ok ? 'btn primary' : 'btn', disabled: !ok, onclick: () => act(() => api('/api/review/' + it.id + '/approve', { method: 'POST', body: {} }), 'Added to the library and shared with your mesh').then(load) }, 'Approve'),
        ok ? null : h('button', { class: 'btn danger', onclick: () => { if (confirm('This file did not pass the scan. Approve it anyway and share it with your other nodes?')) act(() => api('/api/review/' + it.id + '/approve', { method: 'POST', body: { override: true } }), 'Approved anyway').then(load); } }, 'Approve anyway'),
        h('button', { class: 'btn ghost', onclick: () => act(() => api('/api/review/' + it.id + '/rescan', { method: 'POST' }), 'Scanned again').then(load) }, 'Scan again'),
        h('button', { class: 'btn danger', onclick: () => { if (confirm('Delete this file permanently?')) act(() => api('/api/review/' + it.id + '/reject', { method: 'POST' }), 'Deleted').then(load); } }, 'Reject')));
  };

  // many episodes of one show: one panel, one button
  const groupPanel = (g, load) => {
    const passed = g.eps.filter((e) => e.scan && e.scan.ok);
    const bad = g.eps.filter((e) => e.scan && !e.scan.ok && !e.scan.hard);
    const unsafe = g.eps.filter((e) => e.scan && e.scan.hard);
    const waiting = g.eps.filter((e) => !e.scan);
    const bulk = async (label, targets, path, body) => {
      let ok = 0, fail = 0;
      busy = true;
      for (const e of targets) {
        try { await api('/api/review/' + e.id + path, { method: 'POST', body }); ok++; } catch { fail++; }
        btnState.textContent = label + ' ' + (ok + fail) + '/' + targets.length + '…';
      }
      busy = false;
      toast(fail ? ok + ' done, ' + fail + ' failed' : ok + ' episodes ' + (path === '/approve' ? 'added to the library and shared with your mesh' : 'deleted'), fail ? 'bad' : 'ok');
      load();
    };
    const btnState = h('span', { class: 'faint' });
    const det = h('details', { class: 'group-details' }, h('summary', null, 'Show the ' + g.eps.length + ' files'), h('div', { class: 'stack' }, g.eps.map((e) => itemPanel(e, load))));
    if (open.has(g.key)) det.open = true;
    det.addEventListener('toggle', () => { det.open ? open.add(g.key) : open.delete(g.key); });
    return h('section', { class: 'panel' },
      h('div', { class: 'panel-head' },
        h('div', null, h('h2', null, g.title), h('div', { class: 'faint' }, showSummary(g) + ' · ' + fmtBytes(g.eps.reduce((a, e) => a + e.size, 0)))),
        h('span', { class: 'verdict ' + (bad.length || unsafe.length ? 'no' : passed.length === g.eps.length ? 'ok' : 'wait') }, unsafe.length ? unsafe.length + ' unsafe' : bad.length ? bad.length + ' need attention' : waiting.length ? waiting.length + ' still scanning' : 'All scans passed')),
      h('p', { class: 'muted' }, [passed.length + ' passed', unsafe.length ? unsafe.length + ' blocked as unsafe (cannot be approved)' : null, bad.length ? bad.length + ' need attention' : null, waiting.length ? waiting.length + ' still scanning' : null].filter(Boolean).join(' · ')),
      h('div', { class: 'row' },
        h('button', { class: 'btn primary', disabled: !passed.length, onclick: (ev) => { ev.target.disabled = true; bulk('Approving', passed, '/approve', {}); } }, 'Approve ' + (passed.length === g.eps.length ? 'all ' : '') + passed.length + (passed.length === g.eps.length ? ' episodes' : ' that passed')),
        bad.length ? h('button', { class: 'btn', onclick: () => { if (confirm(bad.length + ' file(s) did not pass the scan (for example the video index sits at the end of the file). Approve them anyway and share them with your other nodes?')) bulk('Approving', bad, '/approve', { override: true }); } }, 'Approve the ' + bad.length + ' that need attention anyway') : null,
        (() => {
          const sel = h('select', { 'aria-label': 'Set type for all', onchange: async () => {
            if (!sel.value) return;
            busy = true;
            let bad2 = 0;
            for (const e of g.eps) { try { await api('/api/review/' + e.id, { method: 'PATCH', body: { kind: sel.value } }); } catch { bad2++; } }
            busy = false;
            toast(bad2 ? bad2 + ' could not be changed' : 'Marked all as ' + sel.value, bad2 ? 'bad' : 'ok');
            load();
          } }, h('option', { value: '' }, 'Set type for all…'), h('option', { value: 'movie' }, 'Movie'), h('option', { value: 'series' }, 'TV series'), h('option', { value: 'anime' }, 'Anime'));
          return sel;
        })(),
        h('button', { class: 'btn danger', onclick: () => { if (confirm('Delete all ' + g.eps.length + ' files of "' + g.title + '" permanently?')) bulk('Deleting', g.eps, '/reject'); } }, 'Reject all'),
        btnState),
      det);
  };

  const load = async () => {
    const d = await api('/api/review');
    S.review = d.items.length;
    const b = $('#review-badge');
    if (b) { b.textContent = S.review; b.classList.toggle('hidden', !S.review); }
    if (!d.items.length) return list.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'Nothing waiting'), 'New downloads, uploads and imports will show up here.'));
    const groups = groupItems(d.items);
    list.replaceChildren(...groups.map((g) => (g.key && g.eps.length > 1 ? groupPanel(g, load) : itemPanel(g.eps[0], load))));
  };
  await load();
  poll(() => { if (!busy) load().catch(() => {}); }, 6000);
}

// ------------------------------------------------------------------ mesh
const STEPS = ['Heartbeat', 'Need sync?', 'Request', 'Answer', 'Transfer'];
function stepStates(live) {
  const st = (live && live.stage) || '';
  const s = ['idle', 'idle', 'idle', 'idle', 'idle'];
  const fill = (n, last) => { for (let i = 0; i < n; i++) s[i] = 'done'; if (last) s[n] = last; };
  switch (st) {
    case 'heartbeat': fill(0, 'active'); break;
    case 'in sync': fill(5); break;
    case 'need sync': fill(1, 'active'); break;
    case 'requested': fill(2, 'active'); break;
    case 'waiting': fill(3, 'wait'); break;
    case 'approved': fill(4, 'active'); break;
    case 'declined': fill(3, 'bad'); break;
    case 'interrupted': fill(4, 'bad'); break;
    case 'offline': case 'refused': fill(0, 'bad'); break;
    default: break;
  }
  return s;
}
const STAGE_TEXT = {
  heartbeat: 'Sending heartbeat…', 'in sync': 'In sync', 'need sync': 'Needs sync', requested: 'Request sent',
  waiting: 'Waiting for a yes or no', approved: 'Approved, transferring', declined: 'Declined', interrupted: 'Interrupted',
  offline: 'Offline', refused: 'Refused', paused: 'Paused on this node', 'peer paused': 'Paused on their side',
};

async function viewMesh(el) {
  const nodeBox = h('section', { class: 'panel' });
  const control = h('section', { class: 'panel' });
  const peersBox = h('div');
  const reqBox = h('section', { class: 'panel' });
  const xferBox = h('section', { class: 'panel hidden' });
  const pairBox = h('section', { class: 'panel' });
  el.replaceChildren(
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Mesh'),
      h('p', null, 'Your nodes ask each other before anything moves. Every transfer starts with a heartbeat and ends with a yes from the side that holds the file.')),
      h('button', { class: 'btn', onclick: () => act(() => api('/api/sync/now', { method: 'POST' }), 'Checking all peers now') }, 'Sync now')),
    nodeBox, control, h('h2', { class: 'shelf-title' }, 'Peers'), peersBox, xferBox, reqBox, pairBox);

  // ---- caps and switches (rendered once, and after saving)
  const drawControl = (pol, gate) => {
    const num = (k, min, max) => h('input', { type: 'number', min, max, value: pol[k], id: 'pol-' + k });
    const hours = (k) => h('select', { id: 'pol-' + k }, Array.from({ length: 24 }, (_, i) => h('option', { value: i, selected: pol[k] === i }, String(i).padStart(2, '0') + ':00')));
    const sw = h('input', { type: 'checkbox', checked: pol.enabled, 'aria-label': 'Sync on or off', onchange: async (e) => {
      const next = { ...collect(), enabled: e.target.checked };
      const r = await act(() => api('/api/sync/policy', { method: 'PUT', body: next }), next.enabled ? 'Sync is on' : 'Sync stopped');
      if (r) { drawControl(r.policy, null); refreshChrome(); } else e.target.checked = !e.target.checked;
    } });
    const mode = h('select', { id: 'pol-mode' }, h('option', { value: 'auto', selected: pol.mode === 'auto' }, 'Say yes automatically (within the caps)'), h('option', { value: 'ask', selected: pol.mode === 'ask' }, 'Ask me first'));
    const kinds = ['movie', 'series', 'anime'].map((k) => h('label', { class: 'row' }, h('input', { type: 'checkbox', checked: !pol.mirror_kinds.length || pol.mirror_kinds.includes(k), 'data-kind': k }), k));
    const collect = () => {
      const v = (k) => $('#pol-' + k, control);
      const n = (k) => parseInt(v(k).value, 10) || 0;
      const picked = kinds.map((l) => $('input', l)).filter((i) => i.checked).map((i) => i.dataset.kind);
      return {
        enabled: sw.checked, mode: v('mode').value,
        max_upload_kib_s: n('max_upload_kib_s'), max_download_kib_s: n('max_download_kib_s'), max_concurrent: n('max_concurrent'),
        min_free_gb: n('min_free_gb'), max_library_gb: n('max_library_gb'), window_start: n('window_start'), window_end: n('window_end'),
        utc_offset: parseInt(v('utc_offset').value, 10) || 0, transcode_threads: n('transcode_threads'), nice: n('nice'),
        mirror_kinds: picked.length === 3 ? [] : picked, batch_gb: n('batch_gb'),
      };
    };
    control.replaceChildren(
      h('div', { class: 'big-switch' + (pol.enabled ? '' : ' off') },
        h('label', { class: 'switch' }, sw, h('span')),
        h('div', { class: 'grow' }, h('strong', null, pol.enabled ? 'Sync is on' : 'Sync is stopped'),
          h('span', { class: 'muted' }, pol.enabled ? (gate ? 'Paused right now: ' + gate : 'Heartbeats go out and this node can fetch and serve.') : 'No heartbeats out, no requests out, every request in is refused, and running transfers stop.'))),
      h('div', { class: 'panel-head', style: null }, h('h2', { class: 'shelf-title' }, 'Limits and hardware caps')),
      h('div', { class: 'grid-fields' },
        field('When another node asks for a file', mode),
        field('Upload cap (KiB/s)', num('max_upload_kib_s', 0, 1000000), '0 = unlimited'),
        field('Download cap (KiB/s)', num('max_download_kib_s', 0, 1000000), '0 = unlimited'),
        field('Parallel streams', num('max_concurrent', 1, 8), 'Tor is faster with several, at a CPU and memory cost'),
        field('Keep this much disk free (GB)', num('min_free_gb', 0, 100000), 'Sync pauses below this'),
        field('Library size cap (GB)', num('max_library_gb', 0, 1000000), '0 = no cap'),
        field('Largest request (GB)', num('batch_gb', 0, 100000), '0 = no limit'),
        field('Sync window starts', hours('window_start'), 'Same start and end = any time'),
        field('Sync window ends', hours('window_end')),
        field('Hours from UTC', h('input', { type: 'number', min: -12, max: 14, value: pol.utc_offset, id: 'pol-utc_offset' })),
        field('Transcode threads', num('transcode_threads', 1, 16)),
        field('Transcode niceness (0–19)', num('nice', 0, 19), 'Higher = gentler on the machine')),
      h('div', { class: 'row', style: null }, h('span', { class: 'muted' }, 'Mirror:'), kinds),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { const r = await act(() => api('/api/sync/policy', { method: 'PUT', body: collect() }), 'Limits saved'); if (r) { drawControl(r.policy, gate); refreshChrome(); } } }, 'Save limits')));
  };

  // ---- live sections
  const drawLive = (s) => {
    const n = s.node;
    const t = s.tor;
    nodeBox.replaceChildren(
      h('div', { class: 'panel-head' }, h('h2', null, 'This node: ' + n.name), h('span', { class: 'chip ' + (s.locked ? 'bad' : 'ok') }, h('i'), s.locked ? 'Locked' : 'Unlocked')),
      h('dl', { class: 'kv' },
        h('dt', null, 'Fingerprint'), h('dd', { class: 'mono' }, n.fingerprint),
        h('dt', null, 'Mesh address'), h('dd', null, h('div', { class: 'copyline' }, h('code', null, atHome() ? (n.mesh_addr || '(waiting for Tor)') : 'hidden away from home'), n.mesh_addr ? h('button', { class: 'btn small', onclick: () => copy(n.mesh_addr) }, 'Copy') : null)),
        n.transport === 'tor' && atHome() ? [h('dt', null, 'Access address'), h('dd', null, h('div', { class: 'copyline' }, h('code', null, n.access_onion || '(waiting for Tor)'), n.access_onion ? h('button', { class: 'btn small', onclick: () => copy(n.access_onion) }, 'Copy') : null))] : null,
        h('dt', null, 'Transport'), h('dd', null, n.transport === 'tor' ? 'Tor onion services (mesh and access are separate addresses) · bootstrap ' + t.bootstrap + '%' + (t.error ? ' · ' + t.error : '') : 'Direct HTTP (development mode)'),
        h('dt', null, 'Disk'), h('dd', null, fmtBytes(s.disk.free) + ' free · library ' + fmtBytes(s.disk.library))));

    if (!s.peers.length) peersBox.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'No peers yet'), 'Connect this node to your other houses below.'));
    else peersBox.replaceChildren(h('div', { class: 'grid-2' }, s.peers.map((p) => {
      const live = p.live || {};
      const states = stepStates(live);
      const label = STAGE_TEXT[live.stage] || (p.last_ok ? 'Idle' : 'Not contacted yet');
      return h('section', { class: 'panel peer' },
        h('div', { class: 'head' }, h('h3', null, p.name),
          h('span', { class: 'chip ' + (!p.enabled ? '' : live.online ? 'ok' : live.stage ? 'bad' : '') }, h('i'), !p.enabled ? 'Disabled' : live.online ? 'Online' : live.stage ? 'Unreachable' : 'Unknown'),
          h('label', { class: 'switch', title: 'Talk to this peer' }, h('input', { type: 'checkbox', checked: p.enabled, 'aria-label': 'Enable ' + p.name, onchange: (e) => act(() => api('/api/peers/' + p.node_id + '/enabled', { method: 'POST', body: { enabled: e.target.checked } })) }), h('span'))),
        h('div', { class: 'steps', role: 'list', 'aria-label': 'Sync progress with ' + p.name }, STEPS.map((name, i) => h('div', { class: 'step ' + states[i], role: 'listitem' }, h('b'), name))),
        h('div', { class: 'state' }, h('b', null, label), live.detail ? ' · ' + live.detail : '', live.need ? ' · ' + live.need + ' to fetch' : ''),
        h('div', { class: 'faint' }, 'Last contact ' + ago(p.last_ok) + (live.their_mode ? ' · they answer: ' + (live.their_mode === 'ask' ? 'ask first' : 'automatic') : '')),
        h('div', { class: 'faint mono' }, p.fingerprint),
        h('div', { class: 'row', style: null }, h('button', { class: 'btn small danger', onclick: () => { if (confirm('Unpair ' + p.name + '? It loses access to this node.')) act(() => api('/api/peers/' + p.node_id, { method: 'DELETE' }), 'Unpaired'); } }, 'Unpair')));
    })));

    const inc = s.requests.filter((r) => r.dir === 'in');
    const pend = inc.filter((r) => r.status === 'pending');
    reqBox.replaceChildren(
      h('div', { class: 'panel-head' }, h('h2', null, 'Requests'), pend.length ? h('span', { class: 'chip warn' }, h('i'), pend.length + ' waiting for you') : null),
      pend.length ? h('div', { class: 'eps' }, pend.map((r) => h('div', { class: 'ep' },
        h('span', { class: 'meta' }, h('b', null, r.peer_name), ' asks for ' + r.count + ' item' + (r.count === 1 ? '' : 's') + ' (' + fmtBytes(r.bytes) + ') · ' + ago(r.created)),
        h('button', { class: 'btn small primary', onclick: () => act(() => api('/api/sync/requests/' + r.id + '/approve', { method: 'POST' }), 'Approved') }, 'Say yes'),
        h('button', { class: 'btn small danger', onclick: () => act(() => api('/api/sync/requests/' + r.id + '/deny', { method: 'POST' }), 'Declined') }, 'Say no')))) : null,
      s.requests.length
        ? h('table', { class: 'table' }, h('thead', null, h('tr', null, ['When', 'Direction', 'Peer', 'Items', 'Answer'].map((x) => h('th', null, x)))),
          h('tbody', null, s.requests.slice(0, 12).map((r) => h('tr', null, h('td', null, ago(r.created)), h('td', null, r.dir === 'in' ? 'they asked us' : 'we asked them'), h('td', null, r.peer_name), h('td', null, r.count + ' · ' + fmtBytes(r.bytes)),
            h('td', null, h('span', { class: 'status ' + r.status }, r.status), r.reason ? h('span', { class: 'faint' }, ' ' + r.reason) : null)))))
        : h('p', { class: 'muted' }, 'No requests yet.'));

    xferBox.classList.toggle('hidden', !s.transfers.length);
    xferBox.replaceChildren(h('div', { class: 'panel-head' }, h('h2', null, 'Transfers')), ...s.transfers.map((t2) => {
      const bar = h('i'); bar.style.width = (100 * t2.chunks_done / Math.max(1, t2.chunks_total)).toFixed(0) + '%';
      return h('div', { class: 'row', style: null }, h('span', { class: 'grow' }, t2.title + ' from ' + t2.peer), h('div', { class: 'progress grow' }, bar), h('span', { class: 'muted' }, t2.chunks_done + ' / ' + t2.chunks_total + ' MiB'));
    }));
  };

  // ---- pairing: a request, not a race
  const pairArea = h('div');
  if (!atHome()) pairBox.replaceChildren(homeOnlyNotice('Connecting nodes'));
  else {
    const inviteOut = h('div');
    const openList = h('div');
    const outList = h('div');
    const inList = h('div');
    const joinIn = h('textarea', { class: 'code-box', placeholder: 'Paste an invite code here (it starts with syphon1:)', 'aria-label': 'Invite code from the other node', rows: 4 });
    const sendBtn = h('button', { class: 'btn primary', onclick: async () => {
      const r = await act(() => api('/api/pair/join', { method: 'POST', body: { code: joinIn.value } }), 'Request sent. You are connected as soon as they accept.');
      if (r) { joinIn.value = ''; drawPair(); }
    } }, 'Ask to connect');
    const drawPair = async () => {
      let d; try { d = await api('/api/pair', { quiet: true }); } catch { return; }
      openList.replaceChildren(...(d.invites.length ? [h('p', { class: 'faint' }, 'Unused invite codes')] : []), ...d.invites.map((i) => h('div', { class: 'ep' },
        h('span', { class: 'meta' }, 'Expires in ' + Math.max(1, Math.round((i.expires - Date.now() / 1000) / 3600)) + ' h'),
        h('button', { class: 'btn small danger', onclick: () => act(() => api('/api/pair/invite/' + i.id, { method: 'DELETE' }), 'Invite cancelled').then(drawPair) }, 'Cancel'))));
      inList.replaceChildren(...d.incoming.map((r) => h('div', { class: 'notice' },
        h('div', { class: 'grow' }, h('strong', null, r.name + ' wants to connect'), h('div', { class: 'muted' }, 'Fingerprint ' + r.fingerprint)),
        h('button', { class: 'btn small primary', onclick: () => act(() => api('/api/pair/requests/' + r.id + '/accept', { method: 'POST' }), r.name + ' is now connected').then(() => route()) }, 'Accept'),
        h('button', { class: 'btn small danger', onclick: () => act(() => api('/api/pair/requests/' + r.id + '/deny', { method: 'POST' }), 'Declined').then(drawPair) }, 'Decline'))));
      outList.replaceChildren(...d.outgoing.map((o) => h('div', { class: 'ep' },
        h('span', { class: 'meta' }, h('b', null, o.name), ' ', h('span', { class: 'faint' }, o.detail || '')),
        h('span', { class: 'status ' + (o.status === 'done' ? 'done' : o.status === 'sent' || o.status === 'new' ? 'pending' : 'failed') }, o.status === 'done' ? 'connected' : o.status === 'sent' || o.status === 'new' ? 'waiting' : o.status),
        o.status === 'sent' || o.status === 'new' ? h('button', { class: 'btn small ghost', onclick: () => act(() => api('/api/pair/outgoing/' + o.id, { method: 'DELETE' })).then(drawPair) }, 'Cancel') : null)));
    };
    pairBox.replaceChildren(
      h('div', { class: 'panel-head' }, h('h2', null, 'Connect another node')),
      h('ol', { class: 'step-list' },
        h('li', null, h('div', null, h('strong', null, 'Create an invite code'), h('div', { class: 'muted' }, 'On either node. Send the code to the other owner by message, email or in person.'))),
        h('li', null, h('div', null, h('strong', null, 'Paste it on the other node'), h('div', { class: 'muted' }, 'They press "Ask to connect". That is all they have to do.'))),
        h('li', null, h('div', null, h('strong', null, 'Accept the request'), h('div', { class: 'muted' }, 'It appears here, wherever you are in Syphon. When you accept, both nodes connect by themselves. Nobody has to press anything at the same time.')))),
      inList,
      h('div', { class: 'grid-2' },
        h('div', null, h('h3', null, 'Invite someone'),
          h('p', { class: 'muted' }, 'A code works once and expires after 24 hours.'),
          h('div', { class: 'row' }, h('button', { class: 'btn', onclick: async () => {
            const d = await act(() => api('/api/pair/invite', { method: 'POST' }));
            if (!d) return;
            inviteOut.replaceChildren(
              h('p', null, 'Your fingerprint: ', h('b', { class: 'mono' }, d.fingerprint)),
              h('textarea', { class: 'code-box', readOnly: true, value: d.code, 'aria-label': 'Your invite code' }),
              h('div', { class: 'row' }, h('button', { class: 'btn small', onclick: () => copy(d.code) }, 'Copy code')),
              d.qr ? h('img', { class: 'qr', src: d.qr, alt: 'The invite code as a QR code' }) : null);
            drawPair();
          } }, 'Create invite code')), inviteOut, openList),
        h('div', null, h('h3', null, 'Join with a code'), joinIn, h('div', { class: 'row' }, sendBtn), outList)));
    drawPair();
    poll(drawPair, 3000);
  }

  const first = await api('/api/sync');
  drawControl(first.policy, first.gate);
  drawLive(first);
  poll(async () => {
    try { const s = await api('/api/sync', { quiet: true }); S.sync = s; drawLive(s); } catch { /* transient */ }
  }, 3000);
}

// ------------------------------------------------------------------ vault
function homeOnlyNotice(what) {
  return h('div', { class: 'notice warn' }, h('div', null, h('strong', null, what + ' is only available at home'), h('div', { class: 'muted' }, 'You are connecting from outside the home network. For your safety this part of Syphon stays closed away from home.')));
}

async function viewVault(el) {
  if (!atHome()) return el.replaceChildren(homeOnlyNotice('The Vault'));
  const list = h('div');
  const player = h('div');
  const input = h('input', { type: 'file', accept: 'video/*,.mkv,.avi,.ts,.m2ts', multiple: true, class: 'hidden' });
  const files = h('div', { class: 'uploads' });
  const drop = h('div', { class: 'drop', tabindex: '0', role: 'button', 'aria-label': 'Choose videos for your vault', onclick: () => input.click(), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } } },
    h('strong', null, 'Add to your vault'), h('span', null, 'Drop videos here or click to choose. They are encrypted as they arrive.'));
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); }));

  const load = async () => {
    const d = await api('/api/vault');
    if (!d.items.length) return list.replaceChildren(h('div', { class: 'empty' }, h('strong', null, 'Your vault is empty'), 'Add a video above. Only you can see it, and only from the home network.'));
    list.replaceChildren(h('div', { class: 'eps' }, d.items.map((it) => h('div', { class: 'ep' },
      h('span', { class: 'num' }, '▶'),
      h('span', { class: 'meta' }, h('b', null, it.title), ' ', h('span', { class: 'faint' }, fmtBytes(it.size) + ' · added ' + ago(it.added_at))),
      h('button', { class: 'btn small primary', onclick: () => play(it) }, 'Play'),
      h('button', { class: 'btn small ghost', onclick: () => rename(it) }, 'Rename'),
      h('button', { class: 'btn small danger', onclick: () => { if (confirm('Delete "' + it.title + '" from your vault for good?')) act(() => api('/api/vault/' + it.id, { method: 'DELETE' }), 'Deleted').then(load); } }, 'Delete')))));
  };
  const play = (it) => {
    const v = playerWithFallback('/api/vault/' + it.id + '/stream', { autoplay: true });
    v.addEventListener('error', () => toast('Playback failed. This format may not play in your browser.', 'bad'));
    player.replaceChildren(h('div', { class: 'stage' }, v), h('div', { class: 'row spread' }, h('h2', null, it.title), h('button', { class: 'btn small ghost', onclick: () => { v.pause(); v.removeAttribute('src'); v.load(); player.replaceChildren(); } }, 'Close player')));
    player.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  const rename = (it) => {
    const t = h('input', { type: 'text', value: it.title });
    const close = modal('Rename', h('div', { class: 'grid-fields' }, field('Title', t), h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { if (await act(() => api('/api/vault/' + it.id, { method: 'PATCH', body: { title: t.value } }), 'Renamed')) { close(); load(); } } }, 'Save'))));
  };
  const upload = (f) => {
    const bar = h('i'); bar.style.width = '0%';
    const status = h('span', { class: 'muted' }, 'encrypting');
    files.append(h('div', { class: 'panel' }, h('div', { class: 'row spread' }, h('b', null, f.name), status), h('div', { class: 'progress' }, bar)));
    const x = new XMLHttpRequest();
    x.open('PUT', '/api/vault/upload?name=' + encodeURIComponent(f.name));
    x.setRequestHeader('x-requested-with', 'syphon');
    x.upload.onprogress = (e) => { if (e.lengthComputable) bar.style.width = (100 * e.loaded / e.total).toFixed(1) + '%'; };
    x.onload = () => {
      let d = {}; try { d = JSON.parse(x.responseText); } catch { /* ignore */ }
      if (x.status === 200) { bar.style.width = '100%'; status.textContent = 'in your vault'; load(); }
      else { status.textContent = 'failed'; toast((d.error || 'Upload failed') + ': ' + f.name, 'bad'); }
    };
    x.onerror = () => { status.textContent = 'failed'; toast('Upload failed: ' + f.name, 'bad'); };
    x.send(f);
  };
  input.addEventListener('change', () => { Array.from(input.files).forEach(upload); input.value = ''; });
  drop.addEventListener('drop', (e) => Array.from(e.dataTransfer.files).forEach(upload));

  el.replaceChildren(
    h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Vault'), h('p', null, 'Your private shelf.'))),
    h('div', { class: 'vault-hero' }, h('span', { html: ICON_VAULT }),
      h('div', null, h('strong', null, 'Kept on this node, and nowhere else'),
        h('div', { class: 'muted' }, 'Nothing here syncs to your other nodes, appears in the library, or opens away from home. Each person has their own vault.'))),
    player, drop, input, files, h('div', { class: 'shelf-title' }, 'Your videos'), list);
  await load();
}

// ------------------------------------------------------------------ settings
// ------------------------------------------------------------------ settings > storage
// Drives and network storage (NAS). Every drive holds its own encrypted copy of the folders, new videos go to the
// drive with the most room above its reserve, and a NAS can also be a source of existing videos to pull in.
function storagePanels(into) {
  const root = h('div', { class: 'stack' });
  const gb = (n) => (n / 1073741824).toFixed(n >= 107374182400 ? 0 : 1) + ' GB';
  let editing = false; // a form is open: do not redraw over it
  let data = null;

  const meter = (total, free, reserve, mine) => {
    const used = Math.max(0, total - free);
    const el = h('div', { class: 'sbar', title: gb(free) + ' free of ' + gb(total) + (reserve ? ', ' + gb(reserve) + ' kept free for updates and other needs' : '') });
    // set through the style object: the page's security policy does not allow style attributes, which is why this bar never moved
    const fill = h('i', { class: 'used' });
    fill.style.width = (total ? Math.min(100, 100 * used / total) : 0).toFixed(1) + '%';
    el.append(fill);
    if (total && reserve) { const mark = h('b', { class: 'res', title: 'Syphon stops filling here' }); mark.style.left = Math.max(0, 100 - 100 * reserve / total).toFixed(1) + '%'; el.append(mark); }
    return h('div', null, el, h('small', { class: 'faint' }, gb(free) + ' free of ' + gb(total) + (mine ? ' · Syphon holds ' + gb(mine) : '')));
  };

  const chip = (st) => st.online && st.writable ? h('span', { class: 'chip ok' }, h('i'), 'Connected') : h('span', { class: 'chip ' + (st.online ? 'warn' : 'bad') }, h('i'), st.online ? 'No permission yet' : 'Not connected');

  const reserveInput = (cur, st, save) => {
    const inp = h('input', { type: 'number', min: 0, max: 100000, value: cur == null ? '' : cur, placeholder: 'auto: ' + Math.round(st.reserve / 1073741824), class: 'num', 'aria-label': 'Free space to keep, in GB' });
    inp.addEventListener('change', () => save(inp.value === '' ? null : Math.max(0, parseInt(inp.value, 10) || 0)));
    return h('label', { class: 'row small-row' }, h('span', { class: 'muted' }, 'Keep free:'), inp, h('span', { class: 'muted' }, 'GB'), h('span', { class: 'faint' }, 'blank = chosen from the drive\'s size'));
  };

  const browse = (volId, current, onpick) => {
    let sub = '';
    const list = h('div', { class: 'eps' });
    const here = h('code', null, '/');
    const draw = async () => {
      here.textContent = '/' + sub;
      try {
        const d = await api('/api/storage/volumes/' + volId + '/folders?sub=' + encodeURIComponent(sub), { quiet: true });
        list.replaceChildren(sub ? h('div', { class: 'ep link', onclick: () => { sub = sub.split('/').slice(0, -1).join('/'); draw(); } }, h('span', { class: 'meta' }, '← up')) : null,
          d.folders.length ? d.folders.map((f) => h('div', { class: 'ep link', onclick: () => { sub = sub ? sub + '/' + f : f; draw(); } }, h('span', { class: 'meta' }, '📁 ' + f))) : h('p', { class: 'muted' }, 'No folders in here.'));
      } catch (e) { list.replaceChildren(h('p', { class: 'notice-text' }, e.message)); }
    };
    const close = modal('Choose a folder', h('div', null, h('p', { class: 'muted' }, 'Open folders, then choose the one that holds your videos. Syphon reads it; your files there are not changed.'), h('div', { class: 'row' }, h('span', { class: 'muted' }, 'Looking in:'), here), list,
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: () => { onpick(sub); close(); } }, 'Use this folder'))));
    draw();
  };

  // the folders on a drive or share Syphon pulls existing videos from
  const importsEditor = (volId, list, save) => {
    const rows = list.map((x) => ({ ...x }));
    const box = h('div');
    const draw = () => box.replaceChildren(
      rows.length ? rows.map((r, i) => h('div', { class: 'row' },
        h('code', null, '/' + r.sub),
        h('select', { 'aria-label': 'What is in this folder', onchange: (e) => { r.kind = e.target.value; } },
          [['', 'Work it out from the names'], ['movie', 'Movies'], ['series', 'TV series'], ['anime', 'Anime']].map(([v, l]) => h('option', { value: v, selected: r.kind === v }, l))),
        h('button', { class: 'btn small ghost', onclick: () => { rows.splice(i, 1); draw(); } }, 'Remove'))) : h('p', { class: 'muted' }, 'No folders yet. Syphon only pulls from folders you choose here.'),
      h('div', { class: 'row' },
        h('button', { class: 'btn small', onclick: () => browse(volId, '', (sub) => { if (sub && !rows.some((r) => r.sub === sub)) { rows.push({ sub, kind: '', delete_source: false }); draw(); } else if (!sub) toast('Open a folder first', 'bad'); }) }, 'Add a folder…'),
        h('button', { class: 'btn small primary', onclick: () => save(rows) }, 'Save folders')));
    draw();
    return box;
  };

  const volumeCard = (v) => {
    const vol = v.volume, st = v.status, drain = v.drain;
    const isNas = vol.kind === 'nas';
    const patch = (body, msg) => act(() => api('/api/storage/volumes/' + vol.id, { method: 'PATCH', body }), msg).then(draw);
    const more = h('div', { class: 'hidden' });
    return h('section', { class: 'panel vol' },
      h('div', { class: 'panel-head' }, h('h2', null, (isNas ? '🗄 ' : '💽 ') + vol.label), chip(st), h('span', { class: 'chip' }, isNas ? 'Network storage' : 'Drive')),
      h('p', { class: 'faint' }, vol.path + (isNas && vol.nas && vol.nas.host ? ' · ' + vol.nas.proto.toUpperCase() + ' ' + vol.nas.host + '/' + vol.nas.share : '')),
      st.note ? h('p', { class: 'notice-text' }, st.note, ' ', st.online && !st.writable && data.helper ? 'A request was sent to the node\'s helper; this updates by itself.' : '') : null,
      st.total ? meter(st.total, st.free, st.reserve, v.bytes) : null,
      h('div', { class: 'row' },
        h('label', { class: 'switch', title: 'Use for new videos' }, h('input', { type: 'checkbox', checked: vol.enabled, onchange: (e) => patch({ enabled: e.target.checked }, e.target.checked ? 'New videos can go here' : 'No new videos will go here') }), h('span')),
        h('b', null, vol.enabled ? 'Used for new videos' : 'Not used for new videos'), h('span', { class: 'faint' }, v.files + ' item' + (v.files === 1 ? '' : 's') + ' stored here' + (vol.auto ? ' · added automatically' : ''))),
      reserveInput(vol.reserve_gb, st, (r) => patch({ reserve_gb: r }, 'Saved')),
      drain && drain.running ? h('div', null, h('div', { class: 'progress' }, (() => { const b = h('i'); b.style.width = (drain.total ? 100 * drain.done / drain.total : 0) + '%'; return b; })()), h('small', { class: 'faint' }, 'Moving files off this drive: ' + drain.done + ' of ' + drain.total)) : null,
      drain && drain.error ? h('p', { class: 'notice-text' }, 'Moving stopped: ' + drain.error) : null,
      h('div', { class: 'row' },
        h('button', { class: 'btn small', onclick: () => { more.classList.toggle('hidden'); editing = !more.classList.contains('hidden'); } }, 'Folders to pull videos from…'),
        v.files ? h('button', { class: 'btn small', disabled: drain && drain.running, onclick: () => { if (confirm('Move everything on "' + vol.label + '" to your other drives? New videos stop going here first. This can take a while for a big library.')) act(() => api('/api/storage/volumes/' + vol.id + '/drain', { method: 'POST' }), 'Moving files off this drive').then(draw); } }, 'Move files off') : null,
        h('button', { class: 'btn small danger', onclick: () => { if (confirm('Remove "' + vol.label + '" from this node?' + (isNas ? ' The share is disconnected; the files on it are not deleted.' : ' Nothing on the drive is deleted.'))) act(() => api('/api/storage/volumes/' + vol.id, { method: 'DELETE' }), 'Removed').then(draw); } }, 'Remove')),
      more.appendChild(h('div', null, h('p', { class: 'muted' }, 'Tell Syphon where your existing videos are on this ' + (isNas ? 'NAS' : 'drive') + '. They are copied in (encrypted and safety-scanned like any upload) and the originals stay where they are. Folder names help: Show / Season 2 / 03.mkv is understood as season 2, episode 3 of Show.'),
        importsEditor(vol.id, vol.imports || [], (rows) => patch({ imports: rows }, 'Saved. Syphon will look there shortly.')))) && more);
  };

  const draw = async () => {
    if (editing && data) return;
    try { data = await api('/api/storage', { quiet: true }); } catch (e) { return root.replaceChildren(h('p', { class: 'notice-text' }, e.message)); }
    const sys = data.system;
    const put = (body, msg) => act(() => api('/api/storage', { method: 'PUT', body }), msg).then(draw);

    const overview = h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'How this computer stores videos')),
      h('div', { class: 'choice' },
        h('label', { class: 'row' }, h('input', { type: 'radio', name: 'smode', checked: data.mode === 'all', onchange: () => put({ mode: 'all' }, 'Syphon will use every drive in this computer') }),
          h('span', null, h('b', null, 'This computer is a node: use all its drives. '), h('span', { class: 'muted' }, 'Every internal drive is used automatically, including ones you add later. USB sticks and boot partitions are skipped.'))),
        h('label', { class: 'row' }, h('input', { type: 'radio', name: 'smode', checked: data.mode === 'selected', onchange: () => put({ mode: 'selected' }, 'Syphon will use only the drives you choose') }),
          h('span', null, h('b', null, 'Only the drives I choose. '), h('span', { class: 'muted' }, 'Use this when the computer does other things too: pick below which drives Syphon may fill.')))),
      h('label', { class: 'row' }, h('span', { class: 'muted' }, 'Where new videos go:'),
        h('select', { 'aria-label': 'Placement', onchange: (e) => put({ policy: e.target.value }, 'Saved') },
          h('option', { value: 'most_free', selected: data.policy === 'most_free' }, 'The drive with the most room (spreads them out)'),
          h('option', { value: 'in_order', selected: data.policy === 'in_order' }, 'Fill the first drive, then the next'))),
      h('p', { class: 'faint' }, 'Every drive keeps some space free (shown as the marker on its bar) for updates, the database and scanning, so a drive is never filled to the top. Videos are always stored encrypted, on every drive and on a NAS.'));

    const sysCard = h('section', { class: 'panel vol' },
      h('div', { class: 'panel-head' }, h('div', { class: 'row' }, h('h2', null, '💽 System drive'), chip(sys.status)), h('span', { class: 'chip' }, 'Holds the node\'s own data')),
      h('p', { class: 'faint' }, sys.path),
      sys.status.total ? meter(sys.status.total, sys.status.free, sys.status.reserve, sys.bytes) : null,
      h('div', { class: 'row' },
        h('label', { class: 'switch', title: 'Use for new videos' }, h('input', { type: 'checkbox', checked: sys.enabled, onchange: (e) => put({ system_enabled: e.target.checked }, e.target.checked ? 'New videos can go here' : 'No new videos will go here') }), h('span')),
        h('b', null, sys.enabled ? 'Used for new videos' : 'Not used for new videos'), h('span', { class: 'faint' }, sys.files + ' item' + (sys.files === 1 ? '' : 's') + ' stored here')),
      reserveInput(sys.reserve_gb, sys.status, (r) => put({ system_reserve_gb: r }, 'Saved')),
      !sys.enabled && sys.files && data.volumes.length ? h('div', { class: 'row' }, h('button', { class: 'btn small', onclick: () => { if (confirm('Move the videos from the system drive to your other drives?')) act(() => api('/api/storage/volumes/system/drain', { method: 'POST' }), 'Moving files').then(draw); } }, 'Move videos to the other drives')) : null,
      sys.drain && sys.drain.running ? h('small', { class: 'faint' }, 'Moving: ' + sys.drain.done + ' of ' + sys.drain.total) : null);

    const cards = data.volumes.map(volumeCard);

    // drives found in this computer that are not used yet
    const free = data.drives.filter((d) => !d.in_use && !d.system);
    const found = h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Other drives in this computer')),
      free.length ? h('div', { class: 'eps' }, free.map((d) => h('div', { class: 'ep' },
        h('span', { class: 'meta' }, h('b', null, d.mount), ' ', h('span', { class: 'faint' }, gb(d.total) + ' · ' + gb(d.free) + ' free · ' + d.fstype + (d.removable ? ' · removable' : '') + (d.network ? ' · network' : ''))),
        h('button', { class: 'btn small primary', onclick: () => act(() => api('/api/storage/volumes', { method: 'POST', body: { path: d.mount, label: d.mount.split('/').filter(Boolean).pop() || d.source } }), 'Drive added').then(draw) }, 'Use this drive'))))
        : h('p', { class: 'muted' }, data.mode === 'all' ? 'Every other internal drive is already in use.' : 'No unused drives were found.'));

    // add a folder by hand
    const fp = h('input', { type: 'text', placeholder: '/mnt/disk2  (a drive\'s mount point or any folder)', 'aria-label': 'Folder' });
    const fl = h('input', { type: 'text', placeholder: 'Name, for example Disk 2', 'aria-label': 'Name' });
    const addFolder = h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Add a drive or folder by hand')),
      h('p', { class: 'muted' }, 'Give the full path. For a whole drive give its mount point and Syphon makes a "syphon" folder inside it.'),
      h('div', { class: 'grid-fields' }, field('Path', fp), field('Name', fl)),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { if (await act(() => api('/api/storage/volumes', { method: 'POST', body: { path: fp.value, label: fl.value } }), 'Added')) { fp.value = ''; fl.value = ''; draw(); } } }, 'Add')));

    // NAS
    const proto = h('select', { 'aria-label': 'Type of share' }, h('option', { value: 'smb' }, 'Windows / Samba share (SMB)'), h('option', { value: 'nfs' }, 'NFS share'), h('option', { value: 'mounted' }, 'Already mounted on this computer'));
    const nl = h('input', { type: 'text', placeholder: 'Name, for example Living room NAS', 'aria-label': 'Name' });
    const nh = h('input', { type: 'text', placeholder: 'nas.local or 192.168.1.20', 'aria-label': 'NAS address' });
    const ns = h('input', { type: 'text', placeholder: 'media', 'aria-label': 'Share name' });
    const nu = h('input', { type: 'text', autocomplete: 'off', 'aria-label': 'User name' });
    const np = h('input', { type: 'password', autocomplete: 'new-password', 'aria-label': 'Password' });
    const nm = h('input', { type: 'text', placeholder: '/mnt/nas', 'aria-label': 'Where it is mounted' });
    const nsub = h('input', { type: 'text', value: 'syphon', 'aria-label': 'Folder for Syphon' });
    const netFields = h('div', { class: 'grid-fields' }, field('Address', nh), field('Share name', ns, 'The shared folder on the NAS'), field('User name', nu, 'SMB only'), field('Password', np, 'SMB only. Kept in a file only the system can read.'));
    const mntFields = h('div', { class: 'grid-fields hidden' }, field('Mounted at', nm, 'You mounted the share yourself, for example with /etc/fstab'));
    const sync = () => { const m = proto.value === 'mounted'; netFields.classList.toggle('hidden', m); mntFields.classList.toggle('hidden', !m); };
    proto.addEventListener('change', sync);
    const noTools = (proto.value === 'smb' && !data.tools.smb) || (proto.value === 'nfs' && !data.tools.nfs);
    const nas = h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Link a NAS')),
      h('p', { class: 'muted' }, 'Use a network storage box as another drive. Syphon keeps its encrypted files in a folder you choose on the share, and can also read your existing videos from the folders you pick afterwards.'),
      !data.helper ? h('p', { class: 'faint' }, 'This node has no helper that can mount shares for you, so choose "Already mounted" and mount the share yourself first.') : null,
      h('div', { class: 'grid-fields' }, field('Type', proto), field('Name', nl)),
      netFields, mntFields,
      h('div', { class: 'grid-fields' }, field('Folder for Syphon on the share', nsub, 'Created if it does not exist')),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => {
        const body = { proto: proto.value, label: nl.value, host: nh.value, share: ns.value, user: nu.value, password: np.value, mount: nm.value, sub: nsub.value };
        const r = await act(() => api('/api/storage/nas', { method: 'POST', body }));
        if (r) { toast(r.note || 'Linked', 'ok'); np.value = ''; nl.value = ''; draw(); }
      } }, 'Link this NAS')));

    const imp = data.import;
    const scanBox = (data.volumes.some((v) => (v.volume.imports || []).length) || (sys.imports || []).length) ? h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Pulling in existing videos')),
      h('p', { class: 'muted' }, imp.running ? 'Looking through your folders… ' + imp.imported + ' copied in so far' + (imp.last ? ' (' + imp.last + ')' : '') + '.' : imp.finished ? 'Last look ' + ago(imp.finished) + ': ' + imp.found + ' videos seen, ' + imp.imported + ' copied in' + (imp.failed ? ', ' + imp.failed + ' could not be copied' : '') + '. New files are noticed every few minutes.' : 'Syphon looks through your chosen folders every few minutes while you are signed in.'),
      h('div', { class: 'row' }, h('button', { class: 'btn', disabled: imp.running, onclick: () => act(() => api('/api/storage/scan', { method: 'POST' }), 'Looking now').then(() => setTimeout(draw, 1500)) }, 'Look now'))) : null;

    // the trash: deleted videos wait here before their stored copy is removed, and can be put back
    let trash = { items: [], retention_days: 30 };
    try { trash = await api('/api/trash', { quiet: true }); } catch { /* shown empty */ }
    const trashPanel = h('section', { class: 'panel' },
      h('div', { class: 'panel-head' }, h('h2', null, 'Trash'), trash.items.length ? h('button', { class: 'btn small danger', onclick: () => { if (confirm('Delete the stored copy of everything in the trash now? This cannot be undone.')) act(() => api('/api/trash', { method: 'DELETE' }), 'Trash emptied').then(draw); } }, 'Empty the trash') : null),
      h('p', { class: 'faint' }, 'Deleted videos stay here for ' + trash.retention_days + ' days, then the stored copy is removed. Sending a video that is in the trash again brings it back.'),
      trash.items.length ? h('div', { class: 'eps' }, trash.items.map((it) => h('div', { class: 'ep' },
        h('span', null, h('b', null, it.title), it.season != null && it.episode != null ? ' S' + String(it.season).padStart(2, '0') + 'E' + String(it.episode).padStart(2, '0') : it.year ? ' (' + it.year + ')' : '', ' ', h('small', { class: 'faint' }, 'deleted ' + ago(it.deleted_at) + (it.local === 'present' ? '' : ', stored copy already removed'))),
        h('button', { class: 'btn small', onclick: () => act(() => api('/api/items/' + it.id + '/restore', { method: 'POST', body: {} }), 'Restored').then(draw) }, 'Restore'),
        it.local === 'present' ? h('button', { class: 'btn small danger', onclick: () => { if (confirm('Delete the stored copy of "' + it.title + '" now? This cannot be undone.')) act(() => api('/api/trash/' + it.id, { method: 'DELETE' }), 'Deleted').then(draw); } }, 'Delete now') : null))) : h('p', { class: 'muted' }, 'The trash is empty.'));
    root.replaceChildren(overview, sysCard, ...cards, found, addFolder, nas, scanBox, trashPanel);
    void noTools;
  };
  into.push(root);
  poll(() => { draw(); }, 6000);
}

async function viewSettings(el, arg) {
  const home = atHome();
  const owner = S.me.role === 'owner';
  const tabs = { account: [], node: [], device: [], storage: [] };
  const put = (tab, el) => tabs[tab].push(el);

  // ---- your profile picture
  const pic = h('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp', class: 'hidden', 'aria-label': 'Choose a profile picture' });
  const picShow = h('div', { class: 'profile-pic' });
  const drawPic = () => picShow.replaceChildren(avatarEl(S.me.user, S.me.avatar, 72));
  pic.addEventListener('change', async () => {
    const f = pic.files[0]; pic.value = '';
    if (!f) return;
    try {
      const blob = await shrinkPicture(f);
      const r = await api('/api/me/avatar', { method: 'PUT', raw: blob });
      S.me.avatar = r.avatar; drawPic(); refreshWho(); toast('Profile picture saved', 'ok');
    } catch (e) { toast(e.message, 'bad'); }
  });
  drawPic();
  put('account', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Privacy and cookies')),
    h('p', { class: 'muted' }, 'This site only talks to this node. Your browser never contacts Google, a font service, an advertiser, an analytics service or any other outside site, and the page is built so that it cannot (its security policy forbids it).'),
    h('ul', { class: 'plain' },
      h('li', null, h('b', null, 'Cookie "syphon"'), ': your sign-in. Created when you sign in, gone when you sign out or after 12 hours. Needed to keep you signed in.'),
      h('li', null, h('b', null, 'Cookie "syphon_dev"'), ': marks this browser as a device you signed in from, so this node can tell a known device from a new one. It is only created when you sign in and lasts up to a year; "Trusted devices" below lists it and lets you remove it.'),
      h('li', null, h('b', null, 'This browser\'s own storage'), ': one entry, your light or dark choice. It stays on your device and is never sent anywhere.')),
    h('p', { class: 'faint' }, 'Both cookies are only for signing in and cannot be read by the page\'s scripts. Nothing is set for someone who only visits and does not sign in. There is no tracking, no analytics and no advertising.')));
  put('account', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Your profile')),
    h('div', { class: 'row' }, picShow, h('div', { class: 'grow' }, h('b', null, S.me.user), h('div', { class: 'muted' }, 'This picture shows next to your name at the top. Everyone who signs in to this node can see it.'))),
    h('div', { class: 'row' }, pic, h('button', { class: 'btn primary', onclick: () => pic.click() }, S.me.avatar ? 'Change picture' : 'Choose a picture'),
      S.me.avatar ? h('button', { class: 'btn ghost', onclick: async () => { if (await act(() => api('/api/me/avatar', { method: 'DELETE' }), 'Picture removed')) { S.me.avatar = null; drawPic(); refreshWho(); } } }, 'Remove') : null)));

  // ---- your account: password
  const op = h('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'Current password' });
  const np = h('input', { type: 'password', autocomplete: 'new-password', 'aria-label': 'New password' });
  put('account', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Your password')),
    home ? [
      h('p', { class: 'muted' }, owner ? 'This password also protects the key that encrypts your library. Your videos stay readable; only the key wrapper changes.' : 'Choose something only you know.'),
      h('div', { class: 'grid-fields' }, field('Current password', op), field('New password', np, 'At least 8 characters')),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { if (await act(() => api('/api/password', { method: 'POST', body: { old: op.value, new: np.value } }), 'Password changed')) { op.value = ''; np.value = ''; } } }, 'Change password'),
        owner ? h('button', { class: 'btn danger', onclick: async () => { if (confirm('Lock the library now? Everyone is signed out and playback stops until you sign in again.')) { await act(() => api('/api/lock', { method: 'POST' })); S.me = null; boot(); } } }, 'Lock library now') : null),
    ] : h('p', { class: 'muted' }, 'You can change your password from the home network.')));

  // ---- two-step sign-in
  const totpBox = h('div');
  const drawTotp = async () => {
    const me = await api('/api/me');
    S.me.totp = me.totp;
    if (!home) return totpBox.replaceChildren(h('p', { class: 'muted' }, me.totp ? 'Two-step sign-in is on.' : 'Set up two-step sign-in from the home network.'));
    if (me.totp) {
      return totpBox.replaceChildren(h('p', null, 'Two-step sign-in is on. New devices outside your home network enter a code from your authenticator app instead of waiting for approval.'),
        h('div', { class: 'row' }, h('button', { class: 'btn danger', onclick: () => { if (confirm('Turn off two-step sign-in? New devices away from home will need approval from a device at home instead.')) act(() => api('/api/totp/disable', { method: 'POST' }), 'Two-step sign-in is off').then(drawTotp); } }, 'Turn off')));
    }
    totpBox.replaceChildren(h('p', { class: 'muted' }, 'Away from home, a new device is approved either from a device at home or with a code from an authenticator app. The app is faster when nobody is home.'),
      h('div', { class: 'row' }, h('button', { class: 'btn', onclick: async () => {
        const d = await act(() => api('/api/totp/start', { method: 'POST' }));
        if (!d) return;
        const code = h('input', { type: 'text', autocomplete: 'one-time-code', placeholder: '6-digit code', 'aria-label': 'Code from your authenticator app' });
        totpBox.replaceChildren(h('div', { class: 'qr-row' }, d.qr ? h('img', { class: 'qr', src: d.qr, alt: 'QR code for your authenticator app' }) : null,
          h('div', { class: 'grow' }, h('p', null, 'Scan this with an authenticator app (Aegis, 2FAS, Google Authenticator, or any similar app), then enter the 6-digit code it shows.'),
            h('p', { class: 'faint' }, 'Cannot scan? Enter this key by hand: ', h('code', null, d.secret)),
            h('div', { class: 'row' }, code, h('button', { class: 'btn primary', onclick: async () => { if (await act(() => api('/api/totp/confirm', { method: 'POST', body: { code: code.value } }), 'Two-step sign-in is on')) drawTotp(); } }, 'Confirm')))));
      } }, 'Set up two-step sign-in')));
  };
  put('account', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Two-step sign-in')), totpBox));

  // ---- devices
  const devBox = h('div');
  const drawDevices = async () => {
    const d = await api('/api/my/devices');
    devBox.replaceChildren(d.devices.length ? h('table', { class: 'table' }, h('thead', null, h('tr', null, [owner ? 'Who' : null, 'Device', 'Last seen', ''].filter(Boolean).map((x) => h('th', null, x)))),
      h('tbody', null, d.devices.map((v) => h('tr', null,
        owner ? h('td', null, v.user) : null,
        h('td', null, v.name, ' ', v.id === d.current ? h('span', { class: 'tag you' }, 'this device') : null, v.remember ? h('span', { class: 'tag', title: 'An app on this device signs this person in without the password. Remove the device to end that.' }, 'signs in without password') : null),
        h('td', null, ago(v.last_seen) + (v.last_via === 'remote' ? ' · from outside' : ' · at home')),
        h('td', null, h('button', { class: 'btn small danger', onclick: () => { if (confirm('Remove "' + v.name + '"? It will need approval again to sign in from outside your home network.')) act(() => api('/api/my/devices/' + v.id, { method: 'DELETE' }), 'Device removed').then(drawDevices); } }, 'Remove'))))))
      : h('p', { class: 'muted' }, 'No trusted devices yet. A device becomes trusted when you sign in from home or approve it.'));
  };
  put('account', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Trusted devices')),
    h('p', { class: 'muted' }, 'Signing in on a trusted device skips the extra confirmation when you are away from home.'), devBox));

  // ---- connect from other devices
  const connBox = h('div');
  if (home) {
    api('/api/connect').then((c) => {
      connBox.replaceChildren(
        c.lan_urls.length
          ? h('div', { class: 'qr-row' }, c.qr ? h('img', { class: 'qr', src: c.qr, alt: 'QR code for this node\'s home network address' }) : null,
            h('div', { class: 'grow' }, h('p', null, 'On any phone, tablet or laptop connected to your home network, open:'),
              c.lan_urls.map((u) => h('div', { class: 'copyline' }, h('code', null, u), h('button', { class: 'btn small', onclick: () => copy(u) }, 'Copy'))),
              h('p', { class: 'faint' }, 'Sign in with your name and password. Devices on your network are trusted right away.')))
          : h('p', { class: 'muted' }, c.lan_enabled ? 'No home network address was found. Check that this node is connected to your router.' : 'Network access is switched off for this node (it only listens on this machine). Set access_bind = "0.0.0.0:8096" in config.toml and restart to allow phones and laptops.'),
        c.onion ? h('div', null, h('h3', null, 'From outside your home'), h('p', { class: 'muted' }, 'Away from home, use Tor Browser and open this address. A new device then needs your approval or an authenticator code.'),
          h('div', { class: 'copyline' }, h('code', null, c.onion), h('button', { class: 'btn small', onclick: () => copy(c.onion) }, 'Copy'))) : null,
        c.onion ? connectCodeBox() : null);
    }).catch(() => {});
    put('account', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Open Syphon on your other devices')), connBox));
  }

  // ---- owner-only, home-only
  if (owner && home) {
    const users = h('div');
    const drawUsers = async () => {
      const d = await api('/api/users');
      users.replaceChildren(h('table', { class: 'table' }, h('thead', null, h('tr', null, ['Name', 'Role', ''].map((x) => h('th', null, x)))),
        h('tbody', null, d.users.map((u) => h('tr', null, h('td', null, h('span', { class: 'row' }, avatarEl(u.name, u.avatar, 26), u.name)), h('td', null, u.role),
          h('td', null, u.role === 'owner' ? null : h('button', { class: 'btn small danger', onclick: () => { if (confirm('Delete ' + u.name + '?')) act(() => api('/api/users/' + encodeURIComponent(u.name), { method: 'DELETE' }), 'Deleted').then(drawUsers); } }, 'Delete')))))));
    };
    const nu = h('input', { type: 'text', placeholder: 'Name', 'aria-label': 'New person\'s name' });
    const npw = h('input', { type: 'password', placeholder: 'Password (8+ characters)', autocomplete: 'new-password', 'aria-label': 'New person\'s password' });
    const nr = h('select', { 'aria-label': 'Role' }, h('option', { value: 'viewer' }, 'Viewer: watches only'), h('option', { value: 'contributor' }, 'Contributor: can add and edit'));
    put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'People')), users,
      h('div', { class: 'grid-fields' }, field('Name', nu), field('Password', npw), field('Role', nr)),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { if (await act(() => api('/api/users', { method: 'POST', body: { name: nu.value, password: npw.value, role: nr.value } }), 'Person added')) { nu.value = ''; npw.value = ''; drawUsers(); } } }, 'Add person'))));
    drawUsers();

    // ---- outside access: the VPN box (fast) and Tor (slow)
    const outBox = h('div');
    const drawOutside = async () => {
      const d = await api('/api/outside');
      const addr = h('input', { type: 'text', value: d.vpn_boxes.join(', '), placeholder: 'for example 192.168.1.30', 'aria-label': 'VPN box address' });
      const tor = h('input', { type: 'checkbox', checked: d.tor_access, 'aria-label': 'Reachable through Tor from outside', onchange: async (e) => {
        if (!e.target.checked && !d.vpn_boxes.length && !confirm('Without a VPN box, nobody can reach this node from outside once Tor is off. Turn it off anyway?')) { e.target.checked = true; return; }
        if (!await act(() => api('/api/outside', { method: 'POST', body: { tor_access: e.target.checked } }), e.target.checked ? 'Reachable through Tor again' : 'Tor access from outside is off')) e.target.checked = !e.target.checked;
      } });
      outBox.replaceChildren(
        h('h3', null, 'VPN box'),
        h('p', { class: 'muted' }, 'The fast way in from outside: a small box at home running syphon-vpn, used by the Syphon app. Type the box\'s home-network address so this node knows that its visitors come from outside: they then sign in like anyone outside (approval or authenticator code the first time) and can\'t open the home-only settings.'),
        d.vpn_boxes.length ? null : h('p', { class: 'msg warn' }, 'Until the address is set here, people coming through a VPN box look like they are at home. Set it before giving anyone a VPN code.'),
        h('div', { class: 'row' }, field('VPN box address', addr, 'Several boxes: separate them with commas. Leave empty if you have none.'),
          h('button', { class: 'btn', onclick: () => act(() => api('/api/outside', { method: 'POST', body: { vpn_boxes: addr.value.split(',') } }), 'Saved').then(drawOutside) }, 'Save')),
        d.tor ? h('div', null, h('h3', null, 'Tor'),
          h('label', { class: 'row' }, h('span', { class: 'switch' }, tor, h('span')), h('span', null, 'Also reachable from outside through Tor (slow)')),
          h('p', { class: 'faint' }, 'Tor works without a VPN box but is often too slow to stream. Turning this off only closes the outside address for people; the mesh between houses and grabbing keep using Tor.')) : null);
    };
    put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Outside access')), outBox));
    drawOutside().catch(() => {});

    // library safety: scan everything again
    const safeBox = h('div');
    const drawSafe = async () => {
      let p = { running: false };
      try { p = await api('/api/scan/library', { quiet: true }); } catch { /* ignore */ }
      let sys = {};
      try { sys = await api('/api/system', { quiet: true }); } catch { /* ignore */ }
      const sb = sys.sandbox;
      safeBox.replaceChildren(
        sb ? h('p', { class: sb.ok ? 'faint' : 'notice-text' }, sb.ok ? 'Scanning programs run inside a sandbox (' + sb.how + ').'
          : 'This computer does not allow a sandbox' + (sb.why ? ' (' + sb.why + ')' : '') + '. Files are still scanned in full; the scanning programs just run without the extra wall. In a virtual machine or container this is normal. On a regular install you can allow it with: sudo sysctl -w kernel.unprivileged_userns_clone=1 (Ubuntu 24.04: kernel.apparmor_restrict_unprivileged_userns=0), then restart Syphon.') : null,
        h('p', { class: 'muted' }, 'Every file is scanned when it is uploaded, downloaded or arrives from another node, and nothing from another node joins your library until your node has scanned it. Scan the whole library again after updating Syphon or the virus database (ClamAV, if installed). Anything that now fails is taken out of the library and stops being shared.'),
        p.running ? h('div', null, h('div', { class: 'progress' }, (() => { const b = h('i'); b.style.width = (p.total ? (100 * p.done / p.total) : 0) + '%'; return b; })()), h('span', { class: 'faint' }, 'Scanned ' + p.done + ' of ' + p.total + (p.blocked ? ' · ' + p.blocked + ' blocked' : '')))
          : h('div', { class: 'row' }, h('button', { class: 'btn', onclick: async () => { if (await act(() => api('/api/scan/library', { method: 'POST' }), 'Scanning the library')) drawSafe(); } }, 'Scan the whole library now'),
            p.total ? h('span', { class: 'faint' }, 'Last run: ' + p.done + ' files' + (p.blocked ? ', ' + p.blocked + ' blocked, see Review' : ', all clean')) : null));
      if (p.running) setTimeout(() => { if (document.body.contains(safeBox)) drawSafe(); }, 2000);
    };
    put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Safety scan')), safeBox));
    drawSafe();

    // cast, genres and posters
    const metaBox = h('div', { class: 'muted' }, 'Loading…');
    const drawMeta = () => api('/api/metadata', { quiet: true }).then((m) => {
      metaBox.replaceChildren(h('p', { class: 'muted' }, m.enabled ? 'Syphon looks up descriptions, genres, cast and posters for your titles through Tor, so the sites never see who is asking. Only the title and year are sent. ' + m.found + ' titles have details' + (m.pending ? ', ' + m.pending + ' still to look up' : '') + '.' : 'Looking up details is switched off.'),
        h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => act(() => api('/api/metadata', { method: 'POST' }), 'Looking again for titles that were not found').then(drawMeta) }, 'Look up missing details again')),
        h('p', { class: 'faint' }, m.tmdb ? 'Movies use TMDB.' : 'Movies use Wikidata. For richer movie details add a free key from themoviedb.org as metadata.tmdb_key in config.toml.'));
    }).catch(() => metaBox.replaceChildren(h('p', { class: 'muted' }, 'Not available right now.')));
    put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Details and posters')), metaBox));
    drawMeta();

    // performance: what this machine has and the limits chosen for it (owner, at home)
    if (S.me.role === 'owner' && home) {
      const perfBox = h('div', { class: 'muted' }, 'Loading…');
      const drawPerf = async () => {
        let d;
        try { d = await api('/api/perf', { quiet: true }); } catch { return perfBox.replaceChildren(h('p', { class: 'muted' }, 'Not available right now.')); }
        if (!d.hardware) return perfBox.replaceChildren();
        const hw = d.hardware, t = d.tuning;
        const gb = (mb) => (mb / 1024).toFixed(mb >= 10240 ? 0 : 1) + ' GB';
        const row = (label, value) => h('div', { class: 'line' }, h('span', { class: 'tick na' }, '–'), h('span', null, h('b', null, label + ': '), value));
        const setMode = (dedicated) => act(() => api('/api/perf', { method: 'PUT', body: { dedicated } }), dedicated ? 'Syphon will now use what this computer has' : 'Back to small, fixed limits').then(drawPerf);
        perfBox.replaceChildren(
          h('p', { class: 'muted' }, d.dedicated
            ? 'This computer is only for Syphon, so the limits below are sized from the hardware and kept up to date. Upgrade the processor, memory or internet and they adjust by themselves, within about a minute.'
            : 'This computer does other things too, so Syphon keeps small, fixed limits and stays out of the way.'),
          h('div', { class: 'row' },
            h('label', { class: 'switch', title: 'Dedicated node' }, h('input', { type: 'checkbox', checked: d.dedicated, onchange: (e) => setMode(e.target.checked) }), h('span')),
            h('b', null, d.dedicated ? 'Dedicated node: on' : 'Dedicated node: off'), h('span', { class: 'faint' }, 'Turn on only if nothing else important runs on this computer.')),
          h('div', { class: 'scan' },
            row('Processor', hw.cores + ' core' + (hw.cores === 1 ? '' : 's') + (hw.load1 ? ' (busy level ' + hw.load1.toFixed(1) + ')' : '')),
            row('Memory', gb(hw.ram_mb) + ' total, ' + gb(hw.ram_avail_mb) + ' free'),
            row('Network', d.net_mbps + ' Mb/s' + (hw.link_mbps ? ' (the network card\'s speed)' : hw.observed_mbps >= 1 ? ' (fastest seen so far)' : ' (not measured yet, assuming a modest link)')),
            row('Disk', hw.disk_free_gb + ' GB free of ' + hw.disk_total_gb + ' GB')),
          h('p', null, h('b', null, 'Limits in use')),
          h('div', { class: 'scan' },
            row('Transfers to and from your other nodes', t.streams + ' at once'),
            row('Downloads', t.download_parallel + ' at once'),
            row('Low-bitrate streams for playback', t.transcode_max + ' at once'),
            row('Safety scans', t.scan_parallel + ' at once' + (t.dedicated ? ', antivirus pass ' + (t.scan_window_mib / 1024).toFixed(1) + ' GB, first ' + (t.decode_max_mib / 1024).toFixed(0) + ' GB decoded' : '')),
            row('Uploads from browsers', t.upload_parallel + ' files at once, ' + t.max_uploads + ' in progress')),
          t.notes.length ? h('p', { class: 'faint' }, t.notes.join(' ')) : null);
      };
      put('device', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Performance')), perfBox));
      drawPerf();
      S.timers.push(setInterval(() => { if (document.body.contains(perfBox)) drawPerf(); }, 20000));
    }

    // rest mode and the periodic check
    if (S.me.role === 'owner' && home) {
    const restBox = h('div');
    const drawRest = async () => {
      let d;
      try { d = await api('/api/perf', { quiet: true }); } catch { return; }
      const restSect = (() => {
            const r = d.rest || {};
            const save = (body, msg) => act(() => api('/api/perf', { method: 'PUT', body }), msg).then(() => setTimeout(drawRest, 800));
            const sel = h('select', { 'aria-label': 'Rest mode', onchange: (e) => save({ rest_mode: e.target.value }, 'Saved') },
              h('option', { value: 'auto', selected: r.mode === 'auto' }, 'Automatic (dedicated nodes only)'),
              h('option', { value: 'on', selected: r.mode === 'on' }, 'Always allow resting'),
              h('option', { value: 'off', selected: r.mode === 'off' }, 'Never rest'));
            const mins = h('input', { type: 'number', min: 1, max: 1440, value: r.idle_min || 10, 'aria-label': 'Minutes idle', class: 'num-in', onchange: (e) => save({ rest_idle_min: +e.target.value }, 'Saved') });
            return h('div', { class: 'sect' },
              h('div', { class: 'row spread' }, h('b', null, 'Status'),
                h('span', { class: 'chip ' + (r.resting ? 'warn' : r.active ? 'ok' : ''), title: 'Rest mode slows the background chores of an idle node' }, h('i'), r.resting ? 'Resting for ' + Math.max(1, Math.round((r.resting_secs || 0) / 60)) + ' min' : r.active ? 'Awake, will rest when idle' : (r.mode === 'auto' ? 'Off (this node is set to Shared, change it under Performance or pick Always allow resting)' : 'Off'))),
              (() => { const a = r.activity || {}; const bits = []; if (a.blocked_by) bits.push('Held awake right now: ' + a.blocked_by + '.'); if (a.last_use) bits.push('Last activity: ' + a.last_use + ', ' + (a.last_use_secs < 90 ? 'just now' : Math.round(a.last_use_secs / 60) + ' min ago') + '.'); return bits.length ? h('p', { class: 'faint' }, bits.join(' ')) : null; })(),
              h('p', { class: 'muted' }, 'When nobody is using this node, it stops its housekeeping (folder checks, detail lookups, hardware sampling, drive checks) and does almost nothing. Tor and the web address stay on, so the first request wakes it straight away.'),
              h('div', { class: 'row' }, sel, h('span', { class: 'faint' }, 'after'), mins, h('span', { class: 'faint' }, 'minutes unused')),
              (() => {
                const sn = d.sanity || {}; const l = sn.last;
                const run = h('button', { class: 'btn small', onclick: () => { run.disabled = true; api('/api/sanity', { method: 'POST', body: {} }).then(() => { toast('Check finished', 'ok'); drawRest(); }).catch(() => { run.disabled = false; }); } }, 'Check now');
                return h('div', { class: 'sect' }, h('b', null, 'Periodic check'),
                  h('p', { class: 'faint' }, 'Every ' + (sn.every_hours || 6) + ' hours the node keeps names tidy, retries titles whose details were not found, and looks for problems early.'),
                  l ? h('p', { class: l.ok ? 'faint' : 'notice-text' }, 'Last check ' + ago(l.at) + ': ' + (l.ok ? 'all good' : l.issues.join(' ')) + (l.did && l.did.length ? ' Done: ' + l.did.join('; ') + '.' : '')) : h('p', { class: 'faint' }, 'Has not run yet.'),
                  run);
              })());
          })();
      restBox.replaceChildren(restSect);
    };
    put('device', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Rest mode')), restBox));
    drawRest();
    S.timers.push(setInterval(() => { if (document.body.contains(restBox)) drawRest(); }, 30000));
    }

    // updates
    const updBox = h('div');
    const drawUpd = async () => {
      let u = {};
      try { u = await api('/api/update', { quiet: true }); } catch { /* ignore */ }
      const busy = ['checking', 'building', 'installing'].includes(u.state);
      const ask = (action, msg) => act(() => api('/api/update', { method: 'POST', body: { action } }), msg).then(() => setTimeout(drawUpd, 1500));
      updBox.replaceChildren(
        h('p', null, h('b', null, 'Version ' + (u.current || '')), u.source ? h('span', { class: 'muted' }, ' · updates come from ' + u.source + ', through Tor, and only signed releases are installed') : null),
        u.message ? h('p', { class: u.state === 'failed' || u.state === 'rolledback' ? 'notice-text' : 'muted' }, u.message) : null,
        u.source ? h('div', { class: 'row' },
          h('button', { class: 'btn', disabled: busy, onclick: () => ask('check', 'Checking…') }, busy ? 'Working…' : 'Check for updates'),
          u.state === 'available' ? h('button', { class: 'btn primary', disabled: busy, onclick: () => { if (confirm('Install ' + u.latest + ' now? Syphon restarts, so everyone is signed out and the library locks until you sign in again. If the new version does not start, the old one is put back by itself.')) ask('apply', 'Updating…'); } }, 'Install ' + u.latest) : null,
          u.has_previous ? h('button', { class: 'btn ghost', disabled: busy, onclick: () => { if (confirm('Go back to the previous version?')) ask('rollback', 'Going back…'); } }, 'Go back a version') : null)
          : h('p', { class: 'muted' }, 'Updating is not set up on this machine yet. On the node, run: sudo syphon-ctl update-source set <your GitHub repository address> --signers <your signers file>. See the README, section Updates.'));
      if (busy) setTimeout(() => { if (document.body.contains(updBox)) drawUpd(); }, 4000);
    };
    put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Updates')), updBox));
    drawUpd();

    // power and privacy (read-only here: these need a restart, so they are changed with syphon-ctl)
    const sysBox = h('div', { class: 'muted' }, 'Loading…');
    put('device', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Power and privacy')), sysBox));
    api('/api/system', { quiet: true }).then((d) => {
      const row = (label, value, ok) => h('div', { class: 'line' }, h('span', { class: 'tick ' + (ok === true ? 'ok' : ok === false ? 'no' : 'na') }, ok === true ? '✓' : ok === false ? '✕' : '–'), h('span', null, h('b', null, label + ': '), value));
      sysBox.replaceChildren(h('div', { class: 'scan' },
        row('Power loss', d.persistence === 'always_on' ? 'Always on. Safe if the power fails or the node crashes: everything is saved to disk and unfinished downloads start again by themselves.' : 'On demand. Shuts down cleanly and forgets unfinished downloads and half-received files.', null),
        row('Downloads and searches', d.route === 'tor' ? (d.tor_ready ? 'Go through Tor.' : 'Go through Tor (still connecting, ' + d.tor_progress + '%).') : 'Leave directly, not through Tor.', d.route === 'tor' ? true : d.tor ? false : null),
        d.tor ? (() => {
          const th = d.tor_health || {};
          const parts = [d.tor_ready ? 'Connected.' : 'Connecting (' + d.tor_progress + '%).'];
          if (d.tor_ready && th.listed === true) parts.push('Your address can be found on the Tor network.');
          if (d.tor_ready && th.listed === false) parts.push('Your address cannot be found right now. Syphon keeps checking and restarts Tor by itself if it stays that way.');
          if (th.restarts) parts.push('Restarted ' + th.restarts + (th.restarts === 1 ? ' time' : ' times') + ' since the node started, most recently ' + ago(th.last_restart) + (th.last_reason ? ' (' + th.last_reason + ')' : '') + '. The address stays the same.');
          const btn = h('button', { class: 'btn small', onclick: () => { btn.disabled = true; api('/api/tor/restart', { method: 'POST', body: {} }).then(() => toast('Restarting Tor. It reconnects in a minute or two and the address stays the same.', 'ok')).catch(() => { btn.disabled = false; }); } }, 'Restart Tor');
          return row('Tor connection', h('span', null, parts.join(' '), ' ', btn), d.tor_ready ? (th.listed === false ? false : true) : false);
        })() : null,
        d.tor ? row('Tor bridges', d.bridges ? d.bridges + ' configured. Tor traffic looks like ordinary traffic to your internet provider.' + (d.bridge_missing.length ? ' Missing program for: ' + d.bridge_missing.join(', ') + ' (sudo apt install obfs4proxy snowflake-client).' : '') : (d.tor_ready ? 'None. Add bridges if your country or network blocks Tor, or you do not want your provider to see Tor use: sudo syphon-ctl bridge add "LINE".' : 'None, and Tor is not connected yet (' + d.tor_progress + '%). If this stays stuck, your network may block Tor: get bridges from bridges.torproject.org and run sudo syphon-ctl bridge add "LINE".'), d.bridges ? (d.bridge_missing.length ? false : true) : (d.tor_ready ? null : false)) : null,
        d.tor ? row('Whole computer through Tor', d.system_wide_configured ? 'Prepared. Turn it on with: sudo syphon-ctl torify on' : 'Off. Turn it on with: sudo syphon-ctl torify on', d.system_wide_configured ? true : null) : null),
        h('p', { class: 'faint' }, 'Change these on the node itself with "sudo syphon-ctl persistence on|off" and "sudo syphon-ctl torify on|off". Syphon restarts for them to take effect.'));
    }).catch(() => sysBox.replaceChildren(h('p', { class: 'muted' }, 'Not available right now.')));

    // sources
    const srcBox = h('div');
    const kind = h('select', { 'aria-label': 'Type' }, h('option', { value: 'plex' }, 'Plex'), h('option', { value: 'jellyfin' }, 'Jellyfin'));
    const sn = h('input', { type: 'text', placeholder: 'e.g. Dad\'s Plex', 'aria-label': 'Source name' });
    const su = h('input', { type: 'text', placeholder: 'http://192.168.1.20:32400', 'aria-label': 'Server address' });
    const st = h('input', { type: 'password', placeholder: 'Token or API key', autocomplete: 'off', 'aria-label': 'Token' });
    const drawSources = async () => {
      const d = await api('/api/sources');
      srcBox.replaceChildren(d.sources.length ? h('div', { class: 'eps' }, d.sources.map((x) => h('div', { class: 'ep' },
        h('span', { class: 'meta' }, h('b', null, x.name), ' ', h('span', { class: 'faint' }, x.kind + ' · ' + x.url)),
        h('button', { class: 'btn small danger', onclick: () => { if (confirm('Remove ' + x.name + '?')) act(() => api('/api/sources/' + x.id, { method: 'DELETE' }), 'Source removed').then(drawSources); } }, 'Remove'))))
        : h('p', { class: 'muted' }, 'No servers added yet.'));
    };
    put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Your own servers')),
      h('p', { class: 'muted' }, 'Add a Plex or Jellyfin server you have access to and it shows up as a source on the Add page. The token is stored encrypted and is never shown again.'), srcBox,
      h('div', { class: 'grid-fields' }, field('Type', kind), field('Name', sn), field('Address', su), field('Token or API key', st, kind.value === 'plex' ? 'Plex: your X-Plex-Token' : 'Jellyfin: an API key from the dashboard')),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: async () => { if (await act(() => api('/api/sources', { method: 'POST', body: { kind: kind.value, name: sn.value, url: su.value, token: st.value } }), 'Source added')) { sn.value = ''; su.value = ''; st.value = ''; drawSources(); } } }, 'Add server'))));
    drawSources();

    if (S.sync && S.sync.node.transport === 'tor') {
      const dn = h('input', { type: 'text', placeholder: 'e.g. phone', 'aria-label': 'Device name' });
      const device = h('div');
      const keysBox = h('div');
      let active = false;
      const drawKeys = async () => {
        let d = { keys: [], active: false };
        try { d = await api('/api/access-keys', { quiet: true }); } catch { /* shown as off */ }
        active = d.active;
        keysBox.replaceChildren(
          h('div', { class: 'sect first' }, h('span', { class: 'chip ' + (d.active ? 'warn' : 'ok') }, h('i'), d.active ? 'On: only devices that hold a key can open the outside address' : 'Off: anyone with the outside address can reach the sign-in page'), d.active ? null : h('p', { class: 'faint' }, 'The sign-in page still needs a password.')),
          d.keys.length ? h('div', { class: 'sect' }, h('b', null, 'Keys'), h('div', { class: 'eps' }, d.keys.map((k) => h('div', { class: 'ep' },
            h('span', { class: 'meta' }, h('b', null, k.name), ' ', h('span', { class: 'faint' }, 'key made ' + ago(k.created))),
            h('button', { class: 'btn small danger', onclick: () => { if (confirm('Remove the key for "' + k.name + '"? That device can no longer open the outside address.' + (d.keys.length === 1 ? ' It is the last key, so the extra lock turns off.' : ''))) act(() => api('/api/access-keys/' + encodeURIComponent(k.name), { method: 'DELETE' }), 'Key removed').then(drawKeys); } }, 'Remove key'))))) : null,
          d.keys.length ? h('div', { class: 'sect' }, h('button', { class: 'btn', onclick: () => { if (confirm('Turn the extra lock off? All ' + d.keys.length + ' key(s) are removed and the outside address stops asking for one.')) act(() => api('/api/access-keys', { method: 'DELETE' }), 'Extra lock is off').then(drawKeys); } }, 'Turn the extra lock off')) : null);
      };
      put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Extra lock on the outside address')),
        h('p', { class: 'muted' }, 'Optional. Make the outside (Tor) address answer only devices that hold a key. Create one key per device and import the line in Tor Browser: Settings, Connection, Onion Services Authentication.'),
        h('p', { class: 'faint' }, 'The first key switches the lock on for everyone, so import it on your own device straight away. You are never locked out of your home network, and you can remove keys or turn the lock off here at any time (or on the node with: syphon device all --remove).'),
        keysBox,
        h('div', { class: 'sect' }, h('b', null, 'Add a key'), h('div', { class: 'row' }, dn, h('button', { class: 'btn primary', onclick: async () => {
          if (!active && !confirm('Creating the first key turns the extra lock on: devices without a key can no longer open the outside address. Continue?')) return;
          const r = await act(() => api('/api/access-keys', { method: 'POST', body: { name: dn.value } }));
          if (r) { dn.value = ''; device.replaceChildren(h('p', { class: 'faint' }, 'Shown once. It contains the device\'s private key.'), h('div', { class: 'copyline' }, h('code', null, r.auth_line), h('button', { class: 'btn small', onclick: () => copy(r.auth_line) }, 'Copy'))); drawKeys(); }
        } }, 'Create key')), device)));
      drawKeys();
    }

    // how videos are converted for browsers that cannot play them as they are
    const pbBox = h('div', { class: 'muted' }, 'Loading…');
    api('/api/playback', { quiet: true }).then((d) => {
      const sel = h('select', { 'aria-label': 'Conversion quality', onchange: (e) => act(() => api('/api/playback', { method: 'PUT', body: { quality: e.target.value } }), 'Saved') },
        d.qualities.map((q) => h('option', { value: q.id, selected: q.id === d.quality, title: q.detail }, q.label)));
      const detail = h('p', { class: 'faint' }, (d.qualities.find((q) => q.id === d.quality) || {}).detail);
      sel.addEventListener('change', () => { detail.textContent = (d.qualities.find((q) => q.id === sel.value) || {}).detail; });
      const codecSel = h('select', { 'aria-label': 'Conversion format', onchange: (e) => act(() => api('/api/playback', { method: 'PUT', body: { codec: e.target.value } }), 'Saved') },
        h('option', { value: 'av1', selected: d.codec === 'av1' }, 'AV1 (smaller files)'),
        h('option', { value: 'h264', selected: d.codec === 'h264' }, 'H.264 (plays everywhere)'));
      const codecNote = d.av1_encoder
        ? 'AV1 is ready on this node (' + d.av1_encoder + '). Browsers that cannot show AV1 are given H.264 automatically.'
        : 'This node\'s ffmpeg has no AV1 encoder, so conversions use H.264 for now. Installing a recent ffmpeg with SVT-AV1 switches it on by itself.';
      pbBox.replaceChildren(
        h('p', { class: 'muted' }, 'Most videos play as they are. When a browser cannot play a file (for example an MKV with HEVC video, or 10-bit colour), this node converts it while you watch. Pick how sharp that conversion is. Higher looks better but needs a faster processor and a faster connection. Anyone can pick another quality for one video in the player.'),
        h('div', { class: 'sect' }, h('b', null, 'Sharpness'), h('div', { class: 'row' }, sel), detail),
        h('div', { class: 'sect' }, h('b', null, 'Video format used for conversion'), h('div', { class: 'row' }, codecSel), h('p', { class: 'faint' }, codecNote)),
        h('p', { class: 'faint' }, 'Pictures that only need a different wrapper (most MKV files) are not re-encoded at all, so they keep their original quality.'));
    }).catch(() => pbBox.replaceChildren(h('p', { class: 'muted' }, 'Not available right now.')));
    put('node', h('section', { class: 'panel' }, h('div', { class: 'panel-head' }, h('h2', null, 'Playback and conversion')), pbBox));
  }

  // ---- kill node (owner, at home only). Three screens of warnings, then the typed confirmation.
  if (S.me.role === 'owner' && home) {
    const nodeName = (S.sync && S.sync.node && S.sync.node.name) || S.me.node || '';
    const openKill = () => {
      let step = 0;
      const body = h('div', { class: 'kill' });
      let close = () => {};
      const li = (t) => h('li', null, t);
      const screens = [
        () => [
          h('p', null, h('b', null, 'Kill node removes Syphon from this computer completely.')),
          h('p', { class: 'muted' }, 'This is meant for a computer you are giving away, retiring, or that you no longer trust. It is not a restart and it is not a reset. When it finishes, this node is gone.'),
          h('p', null, 'These things are deleted from this computer:'),
          h('ul', null, li('Every video in the library, including the Review area, the quarantine and the Vault'),
            li('The encryption keys, so nothing that was stored here can ever be opened again, by anyone'),
            li('Your accounts, sign-ins, devices, watch history, settings and the trash'),
            li('This node\'s private Tor address and its place in your mesh'),
            li('The Syphon program, its background service, its updater and its system-wide Tor rules'))
        ],
        () => [
          h('p', null, h('b', null, 'This cannot be undone. There is no recovery and no backup.')),
          h('ul', null, li('Anything that exists only on this node is lost for good. Your other nodes keep their own copies of what they already received, but they cannot get anything back from this one.'),
            li('The Vault is never copied to other nodes. Vault videos are lost for good.'),
            li('The other nodes will see this one as gone. To add this computer to the mesh again you would install Syphon fresh and have it approved like a new node.'),
            li('Programs installed from your system\'s package manager (Tor, ffmpeg, ClamAV and so on) are left in place because other things may use them. Remove them yourself if you want.'),
            li('Videos you already downloaded to other devices are not touched.')),
          h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'kill-ack', onchange: (e) => { next.disabled = !e.target.checked; } }), h('span', null, ' I understand that everything Syphon stores on this computer will be deleted forever.'))
        ],
        () => [
          h('p', null, h('b', null, 'Last step. Prove it is really you.')),
          h('p', { class: 'muted' }, 'Type the node name, type KILL NODE, and enter your password. Nothing is deleted until you press the red button.'),
          h('div', { class: 'grid-fields' },
            field('Node name' + (nodeName ? ' (' + nodeName + ')' : ''), kName),
            field('Type KILL NODE', kPhrase),
            field('Your password', kPw))
        ]
      ];
      const kName = h('input', { type: 'text', autocomplete: 'off', 'aria-label': 'Node name' });
      const kPhrase = h('input', { type: 'text', autocomplete: 'off', 'aria-label': 'Confirmation phrase' });
      const kPw = h('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'Password' });
      const back = h('button', { class: 'btn ghost', onclick: () => { step--; draw(); } }, 'Back');
      const cancel = h('button', { class: 'btn ghost', onclick: () => close() }, 'Cancel, keep my node');
      const next = h('button', { class: 'btn primary', onclick: () => { step++; draw(); } }, 'Continue');
      const go = h('button', { class: 'btn danger solid', disabled: true, onclick: async () => {
        go.disabled = true; go.textContent = 'Removing…';
        try {
          const r = await api('/api/kill', { method: 'POST', body: { password: kPw.value, name: kName.value, phrase: kPhrase.value } });
          close();
          const msg = h('p', null, 'The data is being wiped and the program is stopping. This takes a few seconds.');
          const more = h('p', { class: 'muted' }, 'Checking that it is really gone…');
          document.body.replaceChildren(h('div', { class: 'gone' }, h('h1', null, 'This node is being removed'), msg, more));
          const t0 = Date.now();
          const check = async () => {
            let alive = true;
            try { const c = new AbortController(); setTimeout(() => c.abort(), 4000); await fetch('/api/me', { signal: c.signal, cache: 'no-store' }); } catch (_) { alive = false; }
            if (!alive) { msg.textContent = 'Done. The node has stopped and its data is gone. You can close this window.'; more.textContent = ''; return; }
            if (Date.now() - t0 > 60000) {
              msg.textContent = 'The node is still answering after a minute, so the removal did not finish.';
              more.textContent = 'On the computer that runs it, open a terminal and run: sudo syphon-ctl kill   (or: sudo systemctl enable --now syphon-update.path, then try again).';
              return;
            }
            setTimeout(check, 3000);
          };
          setTimeout(check, 4000);
        } catch (ex) { toast(ex.message, 'bad'); go.disabled = false; go.textContent = 'Delete everything and remove this node'; }
      } }, 'Delete everything and remove this node');
      const ready = () => { go.disabled = !(kName.value.trim() === nodeName && kPhrase.value.trim() === 'KILL NODE' && kPw.value); };
      [kName, kPhrase, kPw].forEach((i) => i.addEventListener('input', ready));
      const draw = () => {
        next.disabled = step === 1;
        body.replaceChildren(h('div', { class: 'row muted' }, 'Step ' + (step + 1) + ' of 3'), ...screens[step](),
          h('div', { class: 'row spread' }, step ? back : cancel, step < 2 ? next : go));
        if (step === 1) next.disabled = true;
      };
      draw();
      close = modal('Kill this node', body);
    };
    put('device', h('section', { class: 'panel danger-zone' }, h('div', { class: 'panel-head' }, h('h2', null, 'Danger zone')),
      h('p', { class: 'muted' }, 'Kill node deletes everything Syphon has on this computer: the library, the Vault, the keys, the accounts and the program itself. It cannot be undone. You are asked several times before anything happens.'),
      h('div', { class: 'row' }, h('button', { class: 'btn danger', onclick: openKill }, 'Kill node…'))));
  }

  // keep the Device panels in an order that fills the two columns evenly
  { const order = ['Performance', 'Rest mode', 'Power and privacy', 'Danger zone'];
    const rank = (n) => { const i = order.indexOf((n.querySelector('h2') || {}).textContent); return i < 0 ? 9 : i; };
    tabs.device.sort((x, y) => rank(x) - rank(y)); }

  // Settings are split by what they are about: you, the node (software), this computer (hardware), and its storage.
  const TABS = [['account', 'Account', 'You: your picture, password and devices.'], ['node', 'Node', 'The node itself, as software: people, outside access, safety, updates and playback.'], ['device', 'Device', 'This computer: its processor, memory and network, power, and removing the node.'], ['storage', 'Storage', 'Where videos are kept on this computer: drives, network storage (NAS) and how much space to leave free.']];
  const avail = owner && home ? TABS : TABS.slice(0, 1);
  const tab = avail.some((t) => t[0] === arg) ? arg : 'account';
  if (tab === 'storage') storagePanels(tabs.storage);
  el.replaceChildren(h('div', { class: 'page-head' }, h('div', null, h('h1', null, 'Settings'))),
    home ? null : homeOnlyNotice('Most settings'),
    avail.length > 1 ? h('div', { class: 'tabbar', role: 'tablist' }, avail.map((t) => h('a', { class: 'tab' + (t[0] === tab ? ' on' : ''), role: 'tab', href: '#/settings/' + t[0] }, t[1]))) : null,
    avail.length > 1 ? h('p', { class: 'muted tabnote' }, avail.find((t) => t[0] === tab)[2]) : null,
    h('div', { class: tab === 'storage' ? 'stack' : 'grid-2 settings-grid' }, ...tabs[tab]));
  drawTotp();
  drawDevices();
}

boot();
