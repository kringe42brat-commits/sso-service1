'use strict';

const PROVIDER_LABELS = { vk:'VK ID', yandex:'Яндекс', mailru:'Mail.ru' };
const ERROR_LABELS = {
  vk_auth_failed:'Ошибка авторизации VK',
  yandex_auth_failed:'Ошибка авторизации Яндекс',
  mailru_auth_failed:'Ошибка авторизации Mail.ru',
  invalid_code:'Недействительный код',
  invalid_state:'Ошибка безопасности — попробуйте снова',
};

// ── TOKEN (in-memory only) ───────────────────
let _token = null, _issuedAt = null;
const TTL = 15 * 60;
const getToken  = () => _token;
const setToken  = t  => { _token = t; _issuedAt = Date.now(); };
const clearToken= () => { _token = null; _issuedAt = null; };

// ── SESSION HISTORY ──────────────────────────
const SK = 'sso_sessions';
const getSessions  = () => { try { return JSON.parse(localStorage.getItem(SK)||'{}'); } catch { return {}; } };
const saveSession  = (p,d) => { const s=getSessions(); s[p]={...d,ts:Date.now()}; localStorage.setItem(SK,JSON.stringify(s)); };

// ── FETCH ────────────────────────────────────
async function apiFetch(url, opts={}, ms=15000) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...opts, credentials:'include', signal:ctrl.signal,
      headers: {
        ...(opts.headers||{}),
        'X-Requested-With':'XMLHttpRequest',
        ...(getToken() ? {Authorization:`Bearer ${getToken()}`} : {}),
      },
    });
  } finally { clearTimeout(tid); }
}

// ── UI ───────────────────────────────────────
const DISPLAY = { 'loading-screen':'flex', 'login-section':'block', 'user-section':'block' };
function show(id) {
  Object.keys(DISPLAY).forEach(s => {
    const el = document.getElementById(s);
    if (el) el.style.display = s === id ? DISPLAY[s] : 'none';
  });
}

function setLoadingMsg(msg) {
  const el = document.getElementById('loading-text');
  if (el) el.textContent = msg;
}

function showToast(msg, type='') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = `toast show${type ? ' toast-'+type : ''}`;
  setTimeout(() => t.classList.remove('show'), 4500);
}

const PM = {vk:'vk', yandex:'ya', mailru:'mail'};
function setButtonLoading(p, on) {
  const btn   = document.getElementById(`btn-${PM[p]}`);
  const arrow = document.getElementById(`arrow-${PM[p]}`);
  if (!btn) return;
  btn.disabled = on;
  arrow.innerHTML = on ? '<span class="spinner-inline"></span>' : '→';
}

// ── LOGIN ─────────────────────────────────────
async function login(p) {
  setButtonLoading(p, true);
  try {
    const res = await apiFetch(`/auth/${p}`, {}, 25000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const { authUrl } = await res.json();
    window.location.href = authUrl;
  } catch(e) {
    setButtonLoading(p, false);
    showToast(
      e.name === 'AbortError'
        ? 'Сервер не отвечает — подождите ~30 сек'
        : 'Ошибка соединения',
      'err'
    );
  }
}

// ── FETCH ME ─────────────────────────────────
async function fetchMe() {
  if (!getToken()) return null;
  try {
    const r = await apiFetch('/auth/me', {}, 20000);
    return r.ok ? r.json() : null;
  } catch { return null; }
}

// ── REFRESH ───────────────────────────────────
async function tryRefresh() {
  try {
    const r = await apiFetch('/auth/refresh', {method:'POST'}, 20000);
    if (!r.ok) return false;
    const { accessToken } = await r.json();
    setToken(accessToken);
    return true;
  } catch { return false; }
}

// ── LOGOUT ───────────────────────────────────
async function logout() {
  try { await apiFetch('/auth/logout', {method:'POST'}, 8000); } catch {}
  localStorage.removeItem(SK);
  clearToken();
  stopCountdown();
  renderSidebar();
  show('login-section');
}

// ── RENDER USER ───────────────────────────────
function renderUser(user) {
  const name     = user.name || user.userId;
  const initials = name.split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2) || '?';

  document.getElementById('user-name').textContent         = name;
  document.getElementById('user-email').textContent        = user.email || 'Email не указан';
  document.getElementById('user-id').textContent           = user.userId;
  document.getElementById('user-email-detail').textContent = user.email || '—';
  document.getElementById('user-provider').textContent     = PROVIDER_LABELS[user.provider] || user.provider;
  document.getElementById('avatar-fallback').textContent   = initials;

  const img = document.getElementById('avatar-img');
  if (user.avatar) {
    img.onload  = () => { document.getElementById('avatar-fallback').style.display='none'; img.style.display=''; };
    img.onerror = () => { img.style.display='none'; };
    img.src = user.avatar;
  }

  const badge = document.getElementById('provider-badge');
  badge.textContent = PROVIDER_LABELS[user.provider] || user.provider;

  saveSession(user.provider, { name, email:user.email, avatar:user.avatar });
  renderSidebar();
  startCountdown();
  show('user-section');

  // Если пришли со страницы-клиента — вернуться туда
  const returnUrl = sessionStorage.getItem('sso_return');
  if (returnUrl) {
    sessionStorage.removeItem('sso_return');
    // Небольшая пауза чтобы успел установиться refresh cookie
    setTimeout(() => { window.location.href = returnUrl; }, 400);
  }
}

// ── COUNTDOWN ────────────────────────────────
let _cd = null;
function startCountdown() {
  stopCountdown();
  const el = document.getElementById('session-countdown');
  if (!el) return;
  const tick = () => {
    const elapsed = _issuedAt ? Math.floor((Date.now()-_issuedAt)/1000) : TTL;
    const left    = Math.max(0, TTL - elapsed);
    const m = Math.floor(left/60).toString().padStart(2,'0');
    const s = (left%60).toString().padStart(2,'0');
    el.textContent = `${m}:${s}`;
    el.style.color = left<120 ? 'var(--err)' : left<300 ? '#d29922' : 'var(--ok)';
    if (left === 0) tryRefresh().then(ok => { if (ok) _issuedAt=Date.now(); });
  };
  tick();
  _cd = setInterval(tick, 1000);
}
function stopCountdown() { if(_cd){clearInterval(_cd);_cd=null;} }

// ── SIDEBAR ───────────────────────────────────
const ICONS = {
  vk:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.579 6.855c.14-.465 0-.806-.662-.806h-2.193c-.558 0-.813.295-.953.619 0 0-1.115 2.719-2.695 4.482-.513.513-.745.675-1.024.675-.14 0-.343-.162-.343-.627V6.855c0-.558-.162-.806-.626-.806H9.642c-.348 0-.557.258-.557.504 0 .528.79.65.871 2.138v3.228c0 .707-.128.836-.406.836-.745 0-2.557-2.731-3.63-5.858C5.715 6.419 5.504 6.05 4.944 6.05H2.75C2.122 6.05 2 6.345 2 6.669c0 .582.745 3.473 3.473 7.299C7.297 16.588 9.909 18 12.279 18c1.442 0 1.62-.325 1.62-.882v-1.97c0-.628.132-.753.576-.753.326 0 .885.163 2.193 1.425 1.494 1.494 1.74 2.18 2.58 2.18h2.193c.627 0 .941-.325.76-.966-.198-.639-.91-1.568-1.86-2.669-.513-.605-1.282-1.257-1.515-1.583-.326-.42-.233-.605 0-.977 0 0 2.681-3.777 2.961-5.059z"/></svg>`,
  yandex:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.32 21h-2.495V13.51H9.21L5.88 21H3.15l3.555-7.88c-1.98-.84-3.03-2.505-3.03-4.74C3.675 5.085 5.88 3 9.45 3H13.32v18zm-2.495-9.495V5.01H9.36c-1.98 0-3.15 1.17-3.15 3.18 0 1.98 1.125 3.315 3.285 3.315h1.33z"/></svg>`,
  mailru:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 13.5L2 7V18h20V7l-10 6.5zM12 11L2 5h20l-10 6z"/></svg>`,
};
const COLORS = {vk:'#0077ff', yandex:'#fc3f1d', mailru:'#168de2'};
const ORDER  = ['vk','yandex','mailru'];

function timeAgo(ts) {
  const d = Math.floor((Date.now()-ts)/1000);
  if (d < 60)    return 'только что';
  if (d < 3600)  return `${Math.floor(d/60)} мин назад`;
  if (d < 86400) return `${Math.floor(d/3600)} ч назад`;
  return `${Math.floor(d/86400)} д назад`;
}

function renderSidebar() {
  const panel = document.getElementById('sidebar-panel');
  if (!panel) return;
  const s = getSessions();
  const count = ORDER.filter(p => s[p]).length;

  panel.innerHTML = `
    <div class="sb-header">
      <span class="sb-title">Аккаунты</span>
      <span class="sb-hint">1 2 3</span>
    </div>
    <div class="sb-list">
      ${ORDER.map((p,i) => {
        const sess = s[p], c = COLORS[p];
        return `<div class="sb-item${sess?' connected':''}" data-p="${p}" style="--c:${c}">
          <div class="sb-icon" style="--c:${c}">${ICONS[p]}${sess?'<span class="sb-dot"></span>':''}</div>
          <div class="sb-info">
            <div class="sb-name">${PROVIDER_LABELS[p]}</div>
            <div class="sb-sub" style="color:${sess?'var(--ok)':'var(--muted2)'}">${sess?timeAgo(sess.ts):`клавиша ${i+1}`}</div>
          </div>
          ${sess&&sess.avatar
            ? `<img class="sb-av" src="${sess.avatar}" onerror="this.style.display='none'" alt="">`
            : sess
              ? `<div class="sb-av-init" style="background:${c}18;color:${c}">${(sess.name||'?')[0].toUpperCase()}</div>`
              : `<span style="color:var(--muted2);font-size:13px">→</span>`
          }
        </div>`;
      }).join('')}
    </div>
    <div class="sb-footer">
      <div class="sb-footer-text">${count} из 3 подключено</div>
      <div class="sb-bar">${ORDER.map(p=>`<div class="sb-seg${s[p]?' on':''}" style="--c:${COLORS[p]}"></div>`).join('')}</div>
    </div>`;

  panel.querySelectorAll('.sb-item').forEach(el => {
    el.addEventListener('click', () => {
      const p = el.dataset.p;
      if (el.classList.contains('connected')) {
        // Подключён — переключаемся или обновляем
        if (getToken()) {
          fetchMe().then(u => { if (u) renderUser(u); });
        } else {
          login(p);
        }
      } else {
        login(p);
      }
    });
  });
}

// ── KEYBOARD ─────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT') return;
  const map = {'1':'vk','2':'yandex','3':'mailru'};
  if (map[e.key] && document.getElementById('login-section').style.display !== 'none') login(map[e.key]);
  if (e.key === 'Escape' && document.getElementById('user-section').style.display !== 'none') logout();
});

// ── CHECK AUTH ────────────────────────────────
async function checkAuth() {
  const wt = setTimeout(() => setLoadingMsg('Сервер запускается, подождите...'), 4000);
  try {
    if (getToken()) {
      const u = await fetchMe();
      if (u) { clearTimeout(wt); renderUser(u); return; }
      clearToken();
    }
    const ok = await tryRefresh();
    if (ok) {
      const u = await fetchMe();
      if (u) { clearTimeout(wt); renderUser(u); return; }
    }
  } catch {}
  clearTimeout(wt);
  show('login-section');
}

// ── INIT ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-vk')?.addEventListener('click',   () => login('vk'));
  document.getElementById('btn-ya')?.addEventListener('click',   () => login('yandex'));
  document.getElementById('btn-mail')?.addEventListener('click', () => login('mailru'));
  document.getElementById('btn-logout')?.addEventListener('click', logout);

  renderSidebar();

  // Читаем токен/ошибку из URL
  const qp = new URLSearchParams(window.location.search);
  const hp = new URLSearchParams(window.location.hash.slice(1));
  history.replaceState(null, '', window.location.pathname);

  const token = qp.get('vk_token') || qp.get('ya_token') || qp.get('mr_token') || qp.get('token') || hp.get('token');
  const error = hp.get('error') || qp.get('error') || qp.get('auth_error');

  if (error) {
    showToast(ERROR_LABELS[error] || `Ошибка: ${error}`, 'err');
    show('login-section');
    return;
  }

  if (token) {
    setToken(token);
    setLoadingMsg('Загружаем профиль...');
    async function tryLoad(attempts=3) {
      for (let i=0; i<attempts; i++) {
        if (i>0) { setLoadingMsg(`Повтор ${i}...`); await new Promise(r=>setTimeout(r,2000)); }
        const u = await fetchMe();
        if (u) { renderUser(u); return; }
      }
      clearToken();
      show('login-section');
      showToast('Не удалось загрузить профиль', 'err');
    }
    tryLoad();
    return;
  }

  checkAuth();
});
