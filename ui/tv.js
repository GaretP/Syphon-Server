'use strict';
/* Syphon on a TV: a big-screen layout that works with nothing but arrow keys, OK and Back.
   Anything that sends those works: a keyboard, a USB or Bluetooth remote, an air mouse, a game controller, media keys.
   Open it at #/tv (the Syphon app's TV mode starts here). It uses app.js's helpers (h, api, S, groupItems, …). */

const IN_APP = /SyphonApp\//.test(navigator.userAgent);
const TV = { items: [], back: null, pad: null, keyHeld: {}, cursorTimer: 0, awake: false, wake: null, player: null };

const tvActive = () => location.hash.startsWith('#/tv');

// ------------------------------------------------------------------ entering and leaving

function tvEnter() {
  document.body.classList.add('tv');
  document.documentElement.setAttribute('data-theme', 'dark');
  clearInterval(S.chromeTimer);
  if (!TV.pad) TV.pad = setInterval(tvPollPad, 50);
}

// The normal view's page for the TV page on screen: a show stays that show, a video that video, the rest the library.
function tvNormalHash() {
  const m = location.hash.match(/^#\/tv\/(show|watch)\/(.+)$/);
  return m ? '#/' + m[1] + '/' + m[2] : '#/library';
}

function tvLeave() {
  document.body.classList.remove('tv', 'tv-nocursor');
  clearInterval(TV.pad); TV.pad = null;
  tvStopPlayer();
  try { document.documentElement.setAttribute('data-theme', localStorage.getItem('syphon-theme') || 'dark'); } catch { /* storage blocked */ }
}

// Ask the Syphon app to keep the screen on while something plays (and the browser too, where it can).
async function tvAwake(on) {
  if (TV.awake === on) return;
  TV.awake = on;
  if (IN_APP) fetch('/__app/api/awake', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ on }) }).catch(() => {});
  try {
    if (on && navigator.wakeLock) TV.wake = await navigator.wakeLock.request('screen');
    else if (!on && TV.wake) { TV.wake.release(); TV.wake = null; }
  } catch { /* not offered here */ }
}

async function tvRoute(rest) {
  tvEnter();
  tvStopPlayer();
  const [sub, ...more] = rest;
  const arg = decodeURIComponent(more.join('/'));
  const root = document.getElementById('app');
  try {
    if (sub === 'show') return await tvShow(root, arg);
    if (sub === 'title') return await tvTitle(root, arg);
    if (sub === 'watch') return await tvWatch(root, arg);
    return await tvHome(root);
  } catch (e) {
    root.replaceChildren(h('div', { class: 'tv-empty' }, h('h1', null, 'Something went wrong'), h('p', null, e.message),
      tvButton('Try again', () => tvRoute(rest), { focus: true })));
  }
}

// ------------------------------------------------------------------ moving around with arrows

const tvVisible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'; };

function tvFocus(el) {
  if (!el) return;
  el.focus({ preventScroll: true });
  el.scrollIntoView({ block: el.closest('.tv-rail') ? 'nearest' : 'center', inline: 'center', behavior: 'smooth' });
  const row = el.closest('.tv-row');
  if (row) row.scrollIntoView({ block: 'center', behavior: 'smooth' });
}

// Find the nearest thing to focus in a direction: along a row for left and right, the closest row for up and down.
function tvMove(dir) {
  const all = [...document.querySelectorAll('[data-nav]')].filter(tvVisible);
  const cur = document.activeElement;
  if (!cur || !all.includes(cur)) return tvFocus(all[0]);
  const r = cur.getBoundingClientRect();
  const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
  let best = null, bestKey = null;
  for (const el of all) {
    if (el === cur) continue;
    const b = el.getBoundingClientRect();
    const x = b.left + b.width / 2, y = b.top + b.height / 2;
    let main, side;
    if (dir === 'left' || dir === 'right') {
      if (Math.abs(y - cy) > Math.max(r.height, b.height) / 2) continue; // same row only
      main = dir === 'left' ? cx - x : x - cx;
      side = Math.abs(y - cy);
    } else {
      main = dir === 'up' ? cy - y : y - cy;
      side = Math.abs(x - cx);
      main = Math.round(main / 24); // things in one row count as equally far
    }
    if (main <= 0) continue;
    const key = [main, side];
    if (!bestKey || key[0] < bestKey[0] || (key[0] === bestKey[0] && key[1] < bestKey[1])) { best = el; bestKey = key; }
  }
  if (best) {
    // coming back to a row: land on the poster you left it on
    const row = best.closest('.tv-rail');
    if ((dir === 'up' || dir === 'down') && row && row.dataset.last) {
      const keep = row.querySelector('[data-key="' + CSS.escape(row.dataset.last) + '"]');
      if (keep) best = keep;
    }
    tvFocus(best);
  }
}

document.addEventListener('focusin', (e) => {
  const rail = e.target.closest && e.target.closest('.tv-rail');
  if (rail && e.target.dataset.key) rail.dataset.last = e.target.dataset.key;
});

function tvButton(label, run, opts = {}) {
  const b = h('button', { class: 'tv-btn' + (opts.primary ? ' primary' : ''), type: 'button', 'data-nav': '', onclick: run }, label);
  if (opts.focus) setTimeout(() => tvFocus(b), 30);
  return b;
}

// one press of a direction or OK, from any input
function tvKey(k, e) {
  if (TV.player) return TV.player.key(k, e);
  if (k === 'up' || k === 'down' || k === 'left' || k === 'right') { tvMove(k); return true; }
  if (k === 'ok') { const a = document.activeElement; if (a && a.matches('[data-nav]') && a.tagName !== 'INPUT') { a.click(); return true; } return false; }
  if (k === 'back') { tvBack(); return true; }
  return false;
}

function tvBack() {
  if (TV.back) return TV.back();
  if (location.hash === '#/tv' || location.hash === '#/tv/') return tvMenu();
  history.length > 1 ? history.back() : (location.hash = '#/tv');
}

const KEYMAP = {
  ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right',
  Enter: 'ok', NumpadEnter: 'ok', ' ': 'play', Select: 'ok',
  Escape: 'back', Backspace: 'back', BrowserBack: 'back', GoBack: 'back', XF86Back: 'back',
  MediaPlayPause: 'play', MediaPlay: 'play', MediaPause: 'play', MediaStop: 'stop',
  MediaTrackNext: 'next', MediaTrackPrevious: 'prev', MediaFastForward: 'ff', MediaRewind: 'rew',
};

document.addEventListener('keydown', (e) => {
  if (!tvActive() || !document.body.classList.contains('tv')) return;
  const typing = e.target && e.target.tagName === 'INPUT' && e.target.type !== 'checkbox';
  let k = KEYMAP[e.key] || (e.keyCode === 461 ? 'back' : null); // 461: "back" on many TV remotes
  if (!k) return;
  if (typing && !['up', 'down', 'back'].includes(k)) return;
  if (k === 'back' && typing && e.key === 'Backspace') return;
  // holding Back for a moment opens the menu (switch profile, settings, leave TV mode)
  if (k === 'back') {
    if (e.repeat) return e.preventDefault();
    TV.keyHeld.back = setTimeout(() => { TV.keyHeld.back = null; tvMenu(); }, 1200);
    e.preventDefault();
    return;
  }
  if (k === 'play' && !TV.player && document.activeElement && document.activeElement.matches('[data-nav]')) k = 'ok';
  if (tvKey(k, e)) e.preventDefault();
});
document.addEventListener('keyup', (e) => {
  if (!tvActive()) return;
  const k = KEYMAP[e.key] || (e.keyCode === 461 ? 'back' : null);
  if (k === 'back' && TV.keyHeld.back) { clearTimeout(TV.keyHeld.back); TV.keyHeld.back = null; tvKey('back', e); e.preventDefault(); }
});

// an air mouse moves the pointer: whatever it points at gets the focus, and the pointer hides when it rests
document.addEventListener('mousemove', (e) => {
  if (!document.body.classList.contains('tv')) return;
  document.body.classList.remove('tv-nocursor');
  clearTimeout(TV.cursorTimer);
  TV.cursorTimer = setTimeout(() => document.body.classList.add('tv-nocursor'), 2500);
  const t = e.target.closest && e.target.closest('[data-nav]');
  if (t && t !== document.activeElement) t.focus({ preventScroll: true });
  if (TV.player) TV.player.poke();
});

// game controllers: D-pad or left stick to move, A = OK, B = back, Start = play/pause, shoulders = jump
const PAD = { 12: 'up', 13: 'down', 14: 'left', 15: 'right', 0: 'ok', 1: 'back', 9: 'play', 4: 'rew', 5: 'ff' };
const padState = { held: {}, next: {} };
function tvPollPad() {
  if (!navigator.getGamepads || !tvActive()) return;
  const now = performance.now();
  const pressed = {};
  for (const gp of navigator.getGamepads()) {
    if (!gp) continue;
    gp.buttons.forEach((b, i) => { if (b.pressed && PAD[i]) pressed[PAD[i]] = true; });
    const [x, y] = [gp.axes[0] || 0, gp.axes[1] || 0];
    if (x < -0.6) pressed.left = true; if (x > 0.6) pressed.right = true;
    if (y < -0.6) pressed.up = true; if (y > 0.6) pressed.down = true;
  }
  for (const k of new Set([...Object.keys(pressed), ...Object.keys(padState.held)])) {
    if (pressed[k] && !padState.held[k]) { padState.held[k] = true; padState.next[k] = now + 420; tvKey(k); }
    else if (pressed[k] && ['up', 'down', 'left', 'right', 'ff', 'rew'].includes(k) && now >= padState.next[k]) { padState.next[k] = now + 130; tvKey(k); }
    else if (!pressed[k]) delete padState.held[k];
  }
}

// ------------------------------------------------------------------ the menu (hold Back)

function tvMenu() {
  if ($('.tv-menu')) return;
  const prev = document.activeElement;
  const close = () => { wrap.remove(); TV.back = savedBack; if (prev && document.contains(prev)) tvFocus(prev); };
  const savedBack = TV.back;
  const items = [];
  if (IN_APP) {
    // the app turns its TV mode off too (asking for its PIN if one is set) and opens the same page in the normal view
    items.push(tvButton('Leave the TV view', () => { tvLeave(); location.href = '/__app/leave-tv?to=' + encodeURIComponent(tvNormalHash()); }));
    items.push(tvButton('Switch profile', () => { location.href = '/__app/profiles'; }));
    items.push(tvButton('App settings', () => { location.href = '/__app/settings?from=' + encodeURIComponent(location.hash); }));
  } else {
    items.push(tvButton('Leave the TV view', () => { const to = tvNormalHash(); tvLeave(); location.hash = to; }));
    items.push(tvButton('Sign out', () => { tvLeave(); logout(); }));
  }
  items.push(tvButton('Back to watching', close, { primary: true }));
  const wrap = h('div', { class: 'tv-menu', role: 'dialog', 'aria-label': 'Menu' },
    h('div', { class: 'tv-menu-box' }, h('h2', null, S.me ? S.me.user : 'Syphon'), items));
  document.body.append(wrap);
  TV.back = close;
  tvFocus(items[0]);
}

// ------------------------------------------------------------------ home: rows of posters

function tvPoster(g, label) {
  const first = g.eps[0];
  const withArt = g.eps.find((e) => e.poster);
  const card = h('button', { class: 'tv-card', type: 'button', 'data-nav': '', 'data-key': g.key || g.id, 'aria-label': g.title,
    onclick: () => { location.hash = g.key ? '#/tv/show/' + encodeURIComponent(g.key) : '#/tv/title/' + encodeURIComponent(first.id); } });
  card.style.setProperty('--h', hue(g.title));
  if (withArt) {
    const img = h('img', { src: '/api/poster/' + withArt.id, alt: '', loading: 'lazy' });
    img.addEventListener('error', () => img.remove());
    card.append(img);
  }
  card.append(h('span', { class: 'tv-card-name' }, g.title));
  const watched = first.pos > 30 && g.eps.length === 1 && first.duration ? Math.min(1, first.pos / first.duration) : 0;
  if (label) card.append(h('span', { class: 'tv-card-tag' }, label));
  if (watched) { const bar = h('i'); bar.style.width = (100 * watched).toFixed(0) + '%'; card.append(h('span', { class: 'tv-card-bar' }, bar)); }
  card.addEventListener('focus', () => tvHero(g));
  return card;
}

function tvRow(title, cards) {
  if (!cards.length) return null;
  return h('section', { class: 'tv-row' }, h('h2', null, title), h('div', { class: 'tv-rail' }, cards));
}

let heroTimer = 0;
function tvHero(g) {
  const hero = $('#tv-hero');
  if (!hero) return;
  const first = g.eps[0];
  const bits = [g.year, g.key ? showSummary(g) : null, ...(genresOf(g).slice(0, 3))].filter(Boolean).join('  ·  ');
  $('#tv-hero-title').textContent = g.title;
  $('#tv-hero-meta').textContent = bits;
  $('#tv-hero-text').textContent = '';
  const art = g.eps.find((e) => e.poster);
  hero.style.setProperty('--h', hue(g.title));
  const bg = $('#tv-hero-bg');
  if (art) bg.replaceChildren(h('img', { src: '/api/poster/' + art.id, alt: '' })); else bg.replaceChildren();
  clearTimeout(heroTimer);
  heroTimer = setTimeout(async () => {
    try {
      const d = await api('/api/items/' + first.id, { quiet: true });
      const ov = d.item && d.item.details && d.item.details.overview;
      if (ov && $('#tv-hero-title') && $('#tv-hero-title').textContent === g.title) $('#tv-hero-text').textContent = ov;
    } catch { /* details are optional */ }
  }, 350);
}

function tvTop() {
  const clock = h('span', { class: 'tv-clock' });
  const tick = () => { clock.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); };
  tick();
  S.timers.push(setInterval(tick, 15000));
  const who = h('button', { class: 'tv-who', type: 'button', 'data-nav': '', onclick: tvMenu, 'aria-label': 'Menu' },
    avatarEl(S.me.user, S.me.avatar, 44), h('span', null, S.me.user));
  const search = h('button', { class: 'tv-btn ghost', type: 'button', 'data-nav': '', onclick: tvSearch }, 'Search');
  return h('header', { class: 'tv-top' }, h('span', { class: 'tv-brand', html: OCTO }), h('span', { class: 'tv-node' }, (S.status && S.status.name) || 'Syphon'), h('span', { class: 'grow' }), search, clock, who);
}

async function tvHome(root, query) {
  TV.back = null;
  const d = await api('/api/library' + (query ? '?q=' + encodeURIComponent(query) : ''));
  TV.items = d.items;
  const groups = groupItems(d.items);
  const rows = [];
  if (query) {
    rows.push(tvRow('Results for "' + query + '"', groups.map((g) => tvPoster(g))));
  } else {
    // continue watching: one per show, the episode you were on
    const seen = new Set(), resume = [];
    for (const i of [...d.items].sort((a, b) => (b.pos_at || 0) - (a.pos_at || 0))) {
      if (!(i.pos > 30 && i.local === 'present')) continue;
      const k = i.group || i.id;
      if (seen.has(k)) continue;
      seen.add(k); resume.push(i);
    }
    rows.push(tvRow('Continue watching', resume.slice(0, 15).map((i) => {
      const c = h('button', { class: 'tv-card', type: 'button', 'data-nav': '', 'data-key': 'r-' + i.id, 'aria-label': i.title, onclick: () => { location.hash = '#/tv/watch/' + encodeURIComponent(i.id); } });
      c.style.setProperty('--h', hue(i.title));
      if (i.poster) c.append(h('img', { src: '/api/poster/' + i.id, alt: '', loading: 'lazy' }));
      c.append(h('span', { class: 'tv-card-name' }, i.title), h('span', { class: 'tv-card-tag' }, [epLabel(i), 'at ' + fmtTime(i.pos)].filter(Boolean).join(' · ')));
      c.addEventListener('focus', () => tvHero({ title: i.title, year: i.year, eps: [i], key: null }));
      return c;
    })));
    const newest = [...groups].sort((a, b) => Math.max(...b.eps.map((e) => e.added_at || 0)) - Math.max(...a.eps.map((e) => e.added_at || 0)));
    if (groups.length >= 6) rows.push(tvRow('Recently added', newest.slice(0, 20).map((g) => tvPoster(g))));
    const byGenre = new Map();
    for (const g of groups) {
      const m = g.kind === 'anime' ? 'Anime' : (genresOf(g).find((x) => MAIN_GENRES.has(x)) || null);
      if (!m) continue;
      if (!byGenre.has(m)) byGenre.set(m, []);
      byGenre.get(m).push(g);
    }
    [...byGenre.entries()].filter(([, gs]) => gs.length >= 2).sort((a, b) => b[1].length - a[1].length).slice(0, 10)
      .forEach(([gen, gs]) => rows.push(tvRow(gen, gs.map((g) => tvPoster(g)))));
    for (const [k, title] of [['movie', 'Movies'], ['series', 'Series'], ['anime', 'All anime']]) {
      const gs = groups.filter((g) => g.kind === k);
      if (gs.length) rows.push(tvRow(title, gs.map((g) => tvPoster(g))));
    }
  }
  const body = rows.filter(Boolean);
  const hero = h('section', { class: 'tv-hero', id: 'tv-hero' }, h('div', { class: 'tv-hero-bg', id: 'tv-hero-bg' }),
    h('div', { class: 'tv-hero-text' }, h('h1', { id: 'tv-hero-title' }, ''), h('p', { class: 'tv-meta', id: 'tv-hero-meta' }), h('p', { class: 'tv-overview', id: 'tv-hero-text' })));
  root.replaceChildren(h('div', { class: 'tv-page tv-home' }, tvTop(), hero,
    body.length ? h('div', { class: 'tv-rows' }, body) : h('div', { class: 'tv-empty' }, h('h1', null, query ? 'Nothing found' : 'Nothing here yet'),
      h('p', null, query ? 'Try other words.' : 'Add videos from the Syphon page on a computer, or wait for your other houses to sync.'))));
  if (query) TV.back = () => tvHome(root);
  const first = root.querySelector('.tv-rail [data-nav]') || root.querySelector('[data-nav]');
  setTimeout(() => tvFocus(first), 30);
  S.timers.push(setInterval(async () => {
    // new videos arrive from the mesh: refresh quietly, keeping the focus where it is
    if (TV.player || document.activeElement && document.activeElement.tagName === 'INPUT') return;
    try { const n = await api('/api/library', { quiet: true }); if (n.items.length !== TV.items.length) { const k = document.activeElement && document.activeElement.dataset.key; await tvHome(root, query); const again = k && root.querySelector('[data-key="' + CSS.escape(k) + '"]'); if (again) tvFocus(again); } } catch { /* try later */ }
  }, 60000));
}

function tvSearch() {
  const root = document.getElementById('app');
  const input = h('input', { type: 'search', class: 'tv-search', placeholder: 'Type a title', 'data-nav': '', 'aria-label': 'Search' });
  const go = tvButton('Search', () => input.value.trim() && tvHome(root, input.value.trim()), { primary: true });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); go.click(); } });
  const box = h('div', { class: 'tv-menu' }, h('div', { class: 'tv-menu-box' }, h('h2', null, 'Search'), input, go,
    h('p', { class: 'tv-hint' }, 'Type with a keyboard or a remote that has one.')));
  const savedBack = TV.back;
  TV.back = () => { box.remove(); TV.back = savedBack; tvMove('down'); };
  document.body.append(box);
  setTimeout(() => input.focus(), 30);
  go.addEventListener('click', () => { box.remove(); TV.back = savedBack; });
}

// ------------------------------------------------------------------ one show: seasons and episodes

async function tvShow(root, key) {
  const d = await api('/api/library');
  const eps = d.items.filter((i) => i.group === key).sort(byEpisode);
  if (!eps.length) { location.hash = '#/tv'; return; }
  const g = finishGroup({ key, eps });
  const seasons = [...new Set(eps.map(seasonOf))].sort((a, b) => a - b);
  const resumeAt = eps.find((e) => e.pos > 30 && e.local === 'present') || eps.find((e) => !e.pos && e.local === 'present') || eps[0];
  let season = seasonOf(resumeAt);
  const list = h('div', { class: 'tv-eps' });
  const drawEps = () => {
    list.replaceChildren(...eps.filter((e) => seasonOf(e) === season).map((e) => {
      const b = h('button', { class: 'tv-ep' + (e.local === 'present' ? '' : ' away'), type: 'button', 'data-nav': '', 'data-key': e.id,
        onclick: () => { if (e.local === 'present') location.hash = '#/tv/watch/' + encodeURIComponent(e.id); } },
        h('span', { class: 'tv-ep-num' }, epLabel(e) || '–'),
        h('span', { class: 'tv-ep-name' }, e.ep_title || e.title),
        h('span', { class: 'tv-ep-state' }, e.local !== 'present' ? 'arriving from the mesh' : e.pos > 30 ? 'at ' + fmtTime(e.pos) : ''));
      return b;
    }));
  };
  const pills = seasons.length > 1 ? h('div', { class: 'tv-rail tv-seasons' }, seasons.map((s) => {
    const p = h('button', { class: 'tv-pill' + (s === season ? ' on' : ''), type: 'button', 'data-nav': '', 'data-key': 's' + s,
      onclick: () => { season = s; pills.querySelectorAll('.tv-pill').forEach((x) => x.classList.toggle('on', x === p)); drawEps(); } }, s ? 'Season ' + s : 'Extras');
    p.addEventListener('focus', () => p.click());
    return p;
  })) : null;
  drawEps();
  const play = tvButton(resumeAt.pos > 30 ? 'Resume ' + epLabel(resumeAt) : 'Play ' + (epLabel(resumeAt) || ''), () => { location.hash = '#/tv/watch/' + encodeURIComponent(resumeAt.id); }, { primary: true, focus: true });
  const overview = h('p', { class: 'tv-overview' });
  root.replaceChildren(h('div', { class: 'tv-page tv-detail' }, tvTop(),
    h('section', { class: 'tv-detail-head' }, tvArt(g), h('div', { class: 'tv-detail-text' },
      h('h1', null, g.title), h('p', { class: 'tv-meta' }, [g.year, showSummary(g), ...genresOf(g).slice(0, 3)].filter(Boolean).join('  ·  ')), overview,
      h('div', { class: 'tv-actions' }, play))),
    pills, list));
  TV.back = () => { location.hash = '#/tv'; };
  api('/api/items/' + eps[0].id, { quiet: true }).then((x) => { overview.textContent = (x.item && x.item.details && x.item.details.overview) || ''; }).catch(() => {});
}

function tvArt(g) {
  const art = g.eps.find((e) => e.poster);
  const box = h('div', { class: 'tv-art' }, art ? h('img', { src: '/api/poster/' + art.id, alt: '' }) : h('span', null, g.title));
  box.style.setProperty('--h', hue(g.title));
  return box;
}

// a film (or anything on its own)
async function tvTitle(root, id) {
  const d = await api('/api/items/' + encodeURIComponent(id));
  const it = d.item;
  const lib = await api('/api/library', { quiet: true }).catch(() => ({ items: [] }));
  const row = lib.items.find((x) => x.id === id) || it;
  const g = { title: it.title, year: it.year, eps: [row], key: null };
  const present = (row.local || it.local) === 'present';
  const actions = present
    ? [tvButton(row.pos > 30 ? 'Resume at ' + fmtTime(row.pos) : 'Play', () => { location.hash = '#/tv/watch/' + encodeURIComponent(id); }, { primary: true, focus: true }),
      row.pos > 30 ? tvButton('Start over', () => { TV.startOver = id; location.hash = '#/tv/watch/' + encodeURIComponent(id); }) : null]
    : [tvButton('This is still arriving from the mesh', () => {}, { focus: true })];
  root.replaceChildren(h('div', { class: 'tv-page tv-detail' }, tvTop(),
    h('section', { class: 'tv-detail-head' }, tvArt(g), h('div', { class: 'tv-detail-text' },
      h('h1', null, it.title), h('p', { class: 'tv-meta' }, [it.year, ...(row.genres || []).slice(0, 3)].filter(Boolean).join('  ·  ')),
      h('p', { class: 'tv-overview' }, (it.details && it.details.overview) || ''),
      h('div', { class: 'tv-actions' }, actions.filter(Boolean))))));
  TV.back = () => { location.hash = '#/tv'; };
}

// ------------------------------------------------------------------ the player

function tvStopPlayer() {
  if (!TV.player) return;
  const p = TV.player;
  TV.player = null;
  p.stop();
}

async function tvWatch(root, id) {
  const d = await api('/api/items/' + encodeURIComponent(id));
  const it = d.item;
  const lib = await api('/api/library', { quiet: true }).catch(() => ({ items: [] }));
  const row = lib.items.find((x) => x.id === id) || {};
  const siblings = row.group ? lib.items.filter((x) => x.group === row.group && x.local === 'present').sort(byEpisode) : [];
  const nextEp = siblings[siblings.findIndex((x) => x.id === id) + 1] || null;
  let pb = { mode: 'direct', duration: 0 }, audioOk = true;
  try { const p = await api('/api/items/' + encodeURIComponent(id) + '/playback', { quiet: true }); pb = p.playback; audioOk = p.audio_ok; } catch { /* play as stored */ }
  // away from home the picture comes over Tor: start on the smooth 480p version
  const quality = S.me.zone !== 'lan' ? 'low' : null;
  let forced = null, offset = 0, lastSaved = 0, hideTimer = 0, seekTarget = null, seekTimer = 0, nextTimer = 0;
  const modeNow = () => forced || (quality ? 'transcode' : pb.mode);
  const converted = () => modeNow() !== 'direct';
  const src = (t) => {
    t = Math.floor(t || 0);
    const m = modeNow();
    if (m === 'remux') return '/api/stream/' + id + '?mode=remux&audio_ok=' + audioOk + '&start=' + t;
    if (m === 'transcode') return '/api/stream/' + id + '?mode=transcode&q=' + (quality || 'medium') + '&codec=' + browserCodec() + '&start=' + t;
    return '/api/stream/' + id;
  };
  const video = h('video', { class: 'tv-video', autoplay: true, playsinline: true, preload: 'auto' });
  const duration = () => (converted() ? pb.duration : video.duration) || pb.duration || 0;
  const position = () => (converted() ? offset : 0) + (video.currentTime || 0);
  const fill = h('i');
  const bar = h('div', { class: 'tv-progress' }, fill);
  const now = h('span'), total = h('span');
  const state = h('div', { class: 'tv-state' });
  const title = [row.title || it.title, epLabel(row), row.ep_title].filter(Boolean).join('  ·  ');
  const osd = h('div', { class: 'tv-osd' }, h('h2', null, title), bar, h('div', { class: 'tv-times' }, now, state, total),
    h('p', { class: 'tv-hint' }, 'OK pause  ·  ◀ ▶ 10 seconds  ·  hold ◀ ▶ to go further  ·  Back to stop'));
  const upNext = h('div', { class: 'tv-next hidden' });
  root.replaceChildren(h('div', { class: 'tv-player' }, video, osd, upNext));

  const draw = () => {
    const t = seekTarget != null ? seekTarget : position();
    const dur = duration();
    fill.style.width = (dur ? Math.min(100, 100 * t / dur) : 0).toFixed(2) + '%';
    now.textContent = fmtTime(t);
    total.textContent = dur ? fmtTime(dur) : '';
    state.textContent = seekTarget != null ? (seekTarget > position() ? '▶▶' : '◀◀') : video.paused ? 'Paused' : '';
  };
  const show = (stay) => {
    osd.classList.add('on');
    draw();
    clearTimeout(hideTimer);
    if (!stay && !video.paused) hideTimer = setTimeout(() => osd.classList.remove('on'), 3500);
  };
  const save = (force) => {
    const p = position();
    if (!force && Math.abs(p - lastSaved) < 10) return;
    lastSaved = p;
    api('/api/progress/' + id, { method: 'PUT', body: { pos: p }, quiet: true }).catch(() => {});
  };
  const load = (start) => {
    offset = converted() ? start || 0 : 0;
    video.src = src(start);
    if (!converted() && start > 5) video.addEventListener('loadedmetadata', () => { if (start < (video.duration || 1e9) - 20) video.currentTime = start; }, { once: true });
    video.play().catch(() => {});
  };
  const jumpTo = (t) => {
    t = Math.max(0, Math.min(t, (duration() || t + 1) - 3));
    if (converted()) load(t); else video.currentTime = t;
    show();
  };
  // pressing ◀ ▶ several times adds up first, then jumps once (a converted stream restarts at the new point)
  const nudge = (dt) => {
    seekTarget = Math.max(0, (seekTarget != null ? seekTarget : position()) + dt);
    show(true);
    clearTimeout(seekTimer);
    seekTimer = setTimeout(() => { const t = seekTarget; seekTarget = null; jumpTo(t); }, converted() ? 700 : 250);
  };
  const toggle = () => { video.paused ? video.play().catch(() => {}) : video.pause(); show(); };
  const fallBack = () => {
    if (modeNow() === 'transcode') { state.textContent = 'This video would not play. Back to return.'; show(true); return; }
    const p = position();
    forced = modeNow() === 'direct' ? 'remux' : 'transcode';
    load(p);
  };
  const finish = () => {
    save(true);
    if (!nextEp) { setTimeout(() => tvBack(), 1500); return; }
    let left = 10;
    const tick = () => {
      upNext.replaceChildren(h('div', null, h('small', null, 'Next'), h('b', null, [epLabel(nextEp), nextEp.ep_title].filter(Boolean).join('  ·  ') || nextEp.title),
        h('span', null, 'Starts in ' + left + ' s  ·  OK to start now  ·  Back to stop')));
      if (left-- <= 0) return playNext();
      nextTimer = setTimeout(tick, 1000);
    };
    upNext.classList.remove('hidden');
    tick();
  };
  const playNext = () => { clearTimeout(nextTimer); location.replace('#/tv/watch/' + encodeURIComponent(nextEp.id)); };

  video.addEventListener('loadedmetadata', () => { if (modeNow() !== 'transcode' && video.videoWidth === 0 && pb.vcodec !== '') fallBack(); });
  video.addEventListener('error', fallBack);
  video.addEventListener('timeupdate', () => { if (!video.paused) save(false); if (osd.classList.contains('on')) draw(); });
  video.addEventListener('play', () => { tvAwake(true); show(); });
  video.addEventListener('pause', () => { save(true); tvAwake(false); show(true); });
  video.addEventListener('waiting', () => { state.textContent = 'Loading…'; osd.classList.add('on'); });
  video.addEventListener('playing', () => draw());
  video.addEventListener('ended', finish);

  const leave = () => { save(true); tvStopPlayer(); history.length > 1 ? history.back() : (location.hash = row.group ? '#/tv/show/' + encodeURIComponent(row.group) : '#/tv'); };
  TV.player = {
    key(k) {
      if (!upNext.classList.contains('hidden')) {
        if (k === 'ok' || k === 'play' || k === 'next') { playNext(); return true; }
        if (k === 'back' || k === 'stop') { clearTimeout(nextTimer); leave(); return true; }
        return true;
      }
      if (k === 'ok' || k === 'play') { toggle(); return true; }
      if (k === 'left' || k === 'rew') { nudge(k === 'rew' ? -30 : -10); return true; }
      if (k === 'right' || k === 'ff') { nudge(k === 'ff' ? 30 : 10); return true; }
      if (k === 'up' || k === 'down') { show(); return true; }
      if (k === 'next' && nextEp) { save(true); playNext(); return true; }
      if (k === 'back' || k === 'stop') { leave(); return true; }
      return false;
    },
    poke() { show(); },
    stop() { clearTimeout(hideTimer); clearTimeout(seekTimer); clearTimeout(nextTimer); save(true); tvAwake(false); video.pause(); video.removeAttribute('src'); video.load(); },
  };
  TV.back = leave;
  video.addEventListener('click', toggle);
  const start = TV.startOver === id ? 0 : row.pos > 30 && row.pos < (pb.duration || 1e9) - 30 ? row.pos : 0;
  TV.startOver = null;
  load(start);
  show();
}
