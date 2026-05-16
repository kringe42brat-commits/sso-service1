// ─── SSO Service — Enhanced Frontend ────────────────────────────────────────
'use strict';

const PROVIDER_LABELS = { vk: 'VK ID', yandex: 'Яндекс', mailru: 'Mail.ru' };
const ERROR_LABELS = {
  vk_auth_failed:     'Ошибка авторизации через VK',
  yandex_auth_failed: 'Ошибка авторизации через Яндекс',
  mailru_auth_failed: 'Ошибка авторизации через Mail.ru',
  invalid_code:       'Недействительный код',
  invalid_state:      'Ошибка безопасности — попробуйте снова',
};

// ─── IN-MEMORY токен ──────────────────────────────────────────────────────────
let _accessToken = null;
let _tokenIssuedAt = null;
let _tokenExpiresIn = 15 * 60; // 15 мин в секундах
const getToken   = () => _accessToken;
const setToken   = (t) => { _accessToken = t; _tokenIssuedAt = Date.now(); };
const clearToken = () => { _accessToken = null; _tokenIssuedAt = null; };

// ─── SESSION HISTORY (localStorage — только имя/аватар, без токенов) ─────────
const SESSIONS_KEY    = 'sso_sessions';
const LAST_UPDATE_KEY = 'sso_last_update';

function getSessions() {
  try { return JSON.parse(localStorage.getItem(SESSIONS_KEY) || '{}'); }
  catch { return {}; }
}
function saveSession(provider, data) {
  const s = getSessions();
  s[provider] = { ...data, lastLogin: Date.now() };
  localStorage.setItem(SESSIONS_KEY, JSON.stringify(s));
}
function setLastUpdate(action) {
  localStorage.setItem(LAST_UPDATE_KEY, JSON.stringify({ time: Date.now(), action }));
  renderUpdateWidget();
}
function getLastUpdate() {
  try { return JSON.parse(localStorage.getItem(LAST_UPDATE_KEY)); } catch { return null; }
}

// ─── FETCH helpers ────────────────────────────────────────────────────────────
async function apiFetch(url, opts = {}, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...opts,
      credentials: 'include',
      signal: ctrl.signal,
      headers: {
        ...(opts.headers || {}),
        'X-Requested-With': 'XMLHttpRequest',
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      },
    });
  } finally { clearTimeout(tid); }
}

// ─── UI helpers ───────────────────────────────────────────────────────────────
function show(id) {
  ['loading-screen', 'login-section', 'user-section'].forEach(s => {
    document.getElementById(s).style.display = s === id ? '' : 'none';
  });
}

function showToast(msg, ok = false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast show${ok ? ' toast-ok' : ''}`;
  setTimeout(() => t.classList.remove('show'), 4500);
}

const PM = { vk: 'vk', yandex: 'ya', mailru: 'mail' };

function setButtonLoading(provider, on) {
  const key   = PM[provider];
  const btn   = document.getElementById(`btn-${key}`);
  const arrow = document.getElementById(`arrow-${key}`);
  if (!btn) return;
  btn.disabled = on;
  arrow.innerHTML = on ? '<span class="spinner-inline"></span>' : '→';
  if (on) document.body.className = provider === 'yandex' ? 'glow-ya' : provider === 'mailru' ? 'glow-mail' : '';
}

// ─── SPARKLE effect ───────────────────────────────────────────────────────────
function sparkle(x, y) {
  for (let i = 0; i < 12; i++) {
    const el = document.createElement('div');
    el.className = 'sparkle-dot';
    const angle  = (i / 12) * Math.PI * 2;
    const dist   = 40 + Math.random() * 40;
    el.style.cssText = `
      left:${x}px; top:${y}px;
      --tx:${Math.cos(angle) * dist}px;
      --ty:${Math.sin(angle) * dist}px;
      background: hsl(${Math.random()*60+180},100%,70%);
    `;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 800);
  }
}

// ─── LOGIN ────────────────────────────────────────────────────────────────────
async function login(provider) {
  setButtonLoading(provider, true);
  try {
    const res = await apiFetch(`/auth/${provider}`, {}, 20000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const { authUrl } = await res.json();
    window.location.href = authUrl;
  } catch (err) {
    setButtonLoading(provider, false);
    document.body.className = '';
    showToast(err.name === 'AbortError'
      ? 'Сервер не отвечает. Подождите 10 секунд.'
      : 'Ошибка соединения с сервером');
  }
}

// ─── FETCH ME ─────────────────────────────────────────────────────────────────
async function fetchMe() {
  if (!getToken()) return null;
  try {
    const res = await apiFetch('/auth/me');
    return res.ok ? res.json() : null;
  } catch { return null; }
}

// ─── REFRESH ──────────────────────────────────────────────────────────────────
async function tryRefresh() {
  try {
    const res = await apiFetch('/auth/refresh', { method: 'POST' }, 10000);
    if (!res.ok) return false;
    const { accessToken } = await res.json();
    setToken(accessToken);
    return true;
  } catch { return false; }
}

// ─── LOGOUT ───────────────────────────────────────────────────────────────────
async function logout() {
  try { await apiFetch('/auth/logout', { method: 'POST' }); } catch {}
  clearToken();
  document.body.className = '';
  stopCountdown();
  setLastUpdate('Выход из аккаунта');
  show('login-section');
  renderSidebar();
}

// ─── RENDER USER ──────────────────────────────────────────────────────────────
function renderUser(user) {
  const name     = user.name || user.userId;
  const initials = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0,2) || '?';

  document.getElementById('user-name').textContent         = name;
  document.getElementById('user-email').textContent        = user.email || 'Email не указан';
  document.getElementById('user-id').textContent           = user.userId;
  document.getElementById('user-email-detail').textContent = user.email || '—';
  document.getElementById('user-provider').textContent     = PROVIDER_LABELS[user.provider] || user.provider;
  document.getElementById('avatar-fallback').textContent   = initials;

  const img = document.getElementById('avatar-img');
  if (user.avatar) {
    img.onload  = () => { document.getElementById('avatar-fallback').style.display='none'; img.style.display=''; };
    img.onerror = () => { img.style.display='none'; document.getElementById('avatar-fallback').style.display=''; };
    img.src = user.avatar;
  }

  const badge = document.getElementById('provider-badge');
  badge.textContent = PROVIDER_LABELS[user.provider] || user.provider;
  badge.className   = `badge badge-${user.provider}`;

  document.body.className = user.provider==='yandex' ? 'glow-ya' : user.provider==='mailru' ? 'glow-mail' : '';

  // Сохраняем сессию в историю
  saveSession(user.provider, { name, email: user.email, avatar: user.avatar });
  setLastUpdate(`Вход через ${PROVIDER_LABELS[user.provider]}`);
  renderSidebar();
  startCountdown();
  show('user-section');
}

// ─── SESSION COUNTDOWN ────────────────────────────────────────────────────────
let _countdownTimer = null;

function startCountdown() {
  stopCountdown();
  const el = document.getElementById('session-countdown');
  if (!el) return;

  function tick() {
    if (!_tokenIssuedAt) return;
    const elapsed = Math.floor((Date.now() - _tokenIssuedAt) / 1000);
    const left    = Math.max(0, _tokenExpiresIn - elapsed);
    const m = Math.floor(left / 60).toString().padStart(2,'0');
    const s = (left % 60).toString().padStart(2,'0');
    el.textContent = `${m}:${s}`;
    el.style.color = left < 120 ? 'var(--err)' : left < 300 ? '#f5a623' : 'var(--ok)';
    if (left === 0) {
      tryRefresh().then(ok => { if (ok) { _tokenIssuedAt = Date.now(); } });
    }
  }
  tick();
  _countdownTimer = setInterval(tick, 1000);
}

function stopCountdown() {
  if (_countdownTimer) { clearInterval(_countdownTimer); _countdownTimer = null; }
}

// ─── LEFT SIDEBAR ─────────────────────────────────────────────────────────────
const PROVIDER_ICONS = {
  vk: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.579 6.855c.14-.465 0-.806-.662-.806h-2.193c-.558 0-.813.295-.953.619 0 0-1.115 2.719-2.695 4.482-.513.513-.745.675-1.024.675-.14 0-.343-.162-.343-.627V6.855c0-.558-.162-.806-.626-.806H9.642c-.348 0-.557.258-.557.504 0 .528.79.65.871 2.138v3.228c0 .707-.128.836-.406.836-.745 0-2.557-2.731-3.63-5.858C5.715 6.419 5.504 6.05 4.944 6.05H2.75C2.122 6.05 2 6.345 2 6.669c0 .582.745 3.473 3.473 7.299C7.297 16.588 9.909 18 12.279 18c1.442 0 1.62-.325 1.62-.882v-1.97c0-.628.132-.753.576-.753.326 0 .885.163 2.193 1.425 1.494 1.494 1.74 2.18 2.58 2.18h2.193c.627 0 .941-.325.76-.966-.198-.639-.91-1.568-1.86-2.669-.513-.605-1.282-1.257-1.515-1.583-.326-.42-.233-.605 0-.977 0 0 2.681-3.777 2.961-5.059z"/></svg>`,
  yandex: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.32 21h-2.495V13.51H9.21L5.88 21H3.15l3.555-7.88c-1.98-.84-3.03-2.505-3.03-4.74C3.675 5.085 5.88 3 9.45 3H13.32v18zm-2.495-9.495V5.01H9.36c-1.98 0-3.15 1.17-3.15 3.18 0 1.98 1.125 3.315 3.285 3.315h1.33z"/></svg>`,
  mailru: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 13.5L2 7V18h20V7l-10 6.5zM12 11L2 5h20l-10 6z"/></svg>`,
};

const PROVIDER_COLORS = { vk: '#0077FF', yandex: '#FC3F1D', mailru: '#168DE2' };
const PROVIDER_ORDER  = ['vk', 'yandex', 'mailru'];

function timeAgo(ts) {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60)   return 'только что';
  if (diff < 3600) return `${Math.floor(diff/60)} мин назад`;
  if (diff < 86400)return `${Math.floor(diff/3600)} ч назад`;
  return `${Math.floor(diff/86400)} д назад`;
}

function renderSidebar() {
  const panel = document.getElementById('sidebar-panel');
  if (!panel) return;
  const sessions = getSessions();

  panel.innerHTML = `
    <div class="sb-header">
      <span class="sb-title">Аккаунты</span>
      <span class="sb-hint">1 2 3</span>
    </div>
    <div class="sb-list">
      ${PROVIDER_ORDER.map((p, i) => {
        const s     = sessions[p];
        const color = PROVIDER_COLORS[p];
        const connected = !!s;
        return `
          <div class="sb-item ${connected ? 'connected' : ''}" data-provider="${p}" title="${connected ? `${s.name} · ${timeAgo(s.lastLogin)}` : `Войти через ${PROVIDER_LABELS[p]}`}">
            <div class="sb-icon" style="--c:${color}">
              ${PROVIDER_ICONS[p]}
              ${connected ? '<span class="sb-dot"></span>' : ''}
            </div>
            <div class="sb-info">
              <div class="sb-name">${PROVIDER_LABELS[p]}</div>
              ${connected
                ? `<div class="sb-time">${timeAgo(s.lastLogin)}</div>`
                : `<div class="sb-login-hint">нажмите ${i+1}</div>`
              }
            </div>
            ${connected && s.avatar
              ? `<img class="sb-avatar" src="${s.avatar}" alt="" onerror="this.style.display='none'">`
              : connected
                ? `<div class="sb-avatar sb-avatar-initial" style="background:${color}22;color:${color}">${(s.name||'?')[0].toUpperCase()}</div>`
                : `<div class="sb-connect-btn" style="color:${color}">→</div>`
            }
          </div>
        `;
      }).join('')}
    </div>
    <div class="sb-footer">
      <div class="sb-footer-text">${Object.keys(sessions).length} из 3 подключено</div>
      <div class="sb-bar">
        ${PROVIDER_ORDER.map(p => `<div class="sb-bar-seg ${sessions[p]?'active':''}" style="--c:${PROVIDER_COLORS[p]}"></div>`).join('')}
      </div>
    </div>
  `;

  // Клик по provider в сайдбаре → логин
  panel.querySelectorAll('.sb-item').forEach(item => {
    item.addEventListener('click', () => {
      const p = item.dataset.provider;
      const keyMap = { vk: 'btn-vk', yandex: 'btn-ya', mailru: 'btn-mail' };
      const btn = document.getElementById(keyMap[p]);
      if (btn && !btn.disabled) {
        btn.classList.add('highlight-pulse');
        setTimeout(() => btn.classList.remove('highlight-pulse'), 600);
        login(p);
      }
    });
  });
}

// ─── BOTTOM-RIGHT UPDATE WIDGET ───────────────────────────────────────────────
let _clockTimer = null;

function renderUpdateWidget() {
  const el  = document.getElementById('update-widget');
  const upd = getLastUpdate();
  if (!el) return;

  // Живые часы
  const now = new Date();
  const hh  = now.getHours().toString().padStart(2,'0');
  const mm  = now.getMinutes().toString().padStart(2,'0');
  const ss  = now.getSeconds().toString().padStart(2,'0');

  el.innerHTML = `
    <div class="upd-clock">${hh}:${mm}:<span class="upd-sec">${ss}</span></div>
    ${upd ? `
      <div class="upd-sep">·</div>
      <div class="upd-info">
        <span class="upd-label">${upd.action}</span>
        <span class="upd-time">${timeAgo(upd.time)}</span>
      </div>
    ` : '<div class="upd-label">Нет активности</div>'}
  `;
}

function startClock() {
  renderUpdateWidget();
  _clockTimer = setInterval(renderUpdateWidget, 1000);
}

// ─── KEYBOARD SHORTCUTS ───────────────────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT') return;
  const map = { '1': 'vk', '2': 'yandex', '3': 'mailru' };
  if (map[e.key]) {
    const keyBtnMap = { vk: 'btn-vk', yandex: 'btn-ya', mailru: 'btn-mail' };
    const btn = document.getElementById(keyBtnMap[map[e.key]]);
    if (btn && !btn.disabled && document.getElementById('login-section').style.display !== 'none') {
      btn.classList.add('highlight-pulse');
      setTimeout(() => { btn.classList.remove('highlight-pulse'); login(map[e.key]); }, 150);
    }
  }
  if (e.key === 'Escape') {
    const logoutBtn = document.getElementById('btn-logout');
    if (logoutBtn && document.getElementById('user-section').style.display !== 'none') logout();
  }
});

// ─── CHECK AUTH ───────────────────────────────────────────────────────────────
async function checkAuth() {
  if (getToken()) {
    const user = await fetchMe();
    if (user) { renderUser(user); return; }
    clearToken();
  }
  const ok = await tryRefresh();
  if (ok) {
    const user = await fetchMe();
    if (user) { renderUser(user); return; }
  }
  show('login-section');
}

// ─── INIT ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Привязка кнопок
  document.getElementById('btn-vk')?.addEventListener('click',   () => login('vk'));
  document.getElementById('btn-ya')?.addEventListener('click',   () => login('yandex'));
  document.getElementById('btn-mail')?.addEventListener('click', () => login('mailru'));
  document.getElementById('btn-logout')?.addEventListener('click', logout);

  // Сайдбар и виджет
  renderSidebar();
  startClock();

  // Читаем fragment
  const hash   = window.location.hash.slice(1);
  const params = new URLSearchParams(hash);
  history.replaceState(null, '', window.location.pathname);

  const token = params.get('token');
  const error = params.get('error');

  if (error) {
    showToast(ERROR_LABELS[error] || `Ошибка: ${error}`);
    show('login-section');
    return;
  }

  if (token) {
    setToken(token);
    fetchMe().then(user => {
      if (user) {
        // Sparkle при успешном входе
        setTimeout(() => {
          const card = document.querySelector('.card');
          if (card) {
            const r = card.getBoundingClientRect();
            sparkle(r.left + r.width/2, r.top + r.height/2);
          }
        }, 300);
        renderUser(user);
      } else { clearToken(); show('login-section'); }
    });
    return;
  }

  checkAuth();
});
