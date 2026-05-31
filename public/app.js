'use strict';

const PROVIDER_LABELS = { vk:'VK ID', yandex:'Яндекс', mailru:'Mail.ru' };
const ERROR_LABELS = {
  vk_auth_failed:     'Ошибка авторизации через VK',
  yandex_auth_failed: 'Ошибка авторизации через Яндекс',
  mailru_auth_failed: 'Ошибка авторизации через Mail.ru',
  invalid_code:       'Недействительный код',
  invalid_state:      'Ошибка безопасности — попробуйте снова',
};

// ── STATE ────────────────────────────────────────────────────────────────────
let _token = null, _issuedAt = null;
let activeProvider = null;      // Провайдер с активной серверной сессией (валидный токен)
let currentViewProvider = null; // Чей профиль сейчас показан на экране
const TOKEN_TTL = 15 * 60;

const getToken   = () => _token;
const setToken   = t => { _token = t; _issuedAt = Date.now(); };
const clearToken = () => { _token = null; _issuedAt = null; };

// ── SESSION STORAGE ──────────────────────────────────────────────────────────
const SK = 'sso_sessions';
const getSessions = () => { try { return JSON.parse(localStorage.getItem(SK) || '{}'); } catch { return {}; } };
const saveSession = (p, d) => { const s = getSessions(); s[p] = { ...d, ts: Date.now() }; localStorage.setItem(SK, JSON.stringify(s)); };
const clearAllSessions = () => localStorage.removeItem(SK);

// ── FETCH ────────────────────────────────────────────────────────────────────
async function apiFetch(url, opts = {}, ms = 15000) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), ms);
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

// ── UI HELPERS ───────────────────────────────────────────────────────────────
function show(id) {
  ['loading-screen', 'login-section', 'user-section'].forEach(s => {
    const el = document.getElementById(s);
    if (!el) return;
    el.style.display = (s === id) ? (s === 'loading-screen' ? 'flex' : 'block') : 'none';
  });
}

function setLoadingMsg(msg) {
  const e = document.getElementById('loading-text');
  if (e) e.textContent = msg;
}

function showToast(msg, ok = false) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = 'toast show' + (ok ? ' toast-ok' : '');
  setTimeout(() => t.classList.remove('show'), 5000);
}

const PM = { vk: 'vk', yandex: 'ya', mailru: 'mail' };
function setButtonLoading(p, on) {
  const btn = document.getElementById(`btn-${PM[p]}`);
  const arrow = document.getElementById(`arrow-${PM[p]}`);
  if (!btn) return;
  btn.disabled = on;
  if (arrow) arrow.innerHTML = on ? '<span class="spinner-inline"></span>' : '→';
}

// ── LOGIN ────────────────────────────────────────────────────────────────────
async function login(provider) {
  setButtonLoading(provider, true);
  try {
    const res = await apiFetch(`/auth/${provider}`, {}, 25000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const { authUrl } = await res.json();
    window.location.href = authUrl;
  } catch (e) {
    setButtonLoading(provider, false);
    showToast(e.name === 'AbortError'
      ? 'Сервер просыпается... подождите ~30 сек и попробуйте снова'
      : 'Ошибка соединения с сервером');
  }
}

// ── AUTH API ─────────────────────────────────────────────────────────────────
async function fetchMe() {
  if (!getToken()) return null;
  try { const r = await apiFetch('/auth/me', {}, 20000); return r.ok ? r.json() : null; }
  catch { return null; }
}

async function tryRefresh() {
  try {
    const r = await apiFetch('/auth/refresh', { method: 'POST' }, 20000);
    if (!r.ok) return false;
    const { accessToken } = await r.json();
    setToken(accessToken);
    return true;
  } catch { return false; }
}

// ── LOGOUT ───────────────────────────────────────────────────────────────────
async function logout() {
  // 1. Отзываем серверную сессию
  try { await apiFetch('/auth/logout', { method: 'POST' }, 8000); } catch {}

  // 2. Полностью очищаем ВСЁ локальное хранилище (чистый лист)
  clearAllSessions();

  // 3. Сбрасываем состояние
  clearToken();
  stopCountdown();
  activeProvider = null;
  currentViewProvider = null;

  // 4. Показываем экран входа
  show('login-section');
  renderSidebar();
  showToast('Вы вышли из системы');
}

// ── RENDER ACTIVE USER (с валидной сессией) ────────────────────────────────
function renderUser(user) {
  activeProvider = user.provider;
  currentViewProvider = user.provider;

  const name = user.name || user.userId;
  const initials = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) || '?';

  document.getElementById('user-name').textContent = name;
  document.getElementById('user-email').textContent = user.email || 'Email не указан';
  document.getElementById('user-id').textContent = user.userId;
  document.getElementById('user-email-detail').textContent = user.email || '—';
  document.getElementById('user-provider').textContent = PROVIDER_LABELS[user.provider] || user.provider;
  document.getElementById('avatar-fallback').textContent = initials;

  const img = document.getElementById('avatar-img');
  if (user.avatar) {
    img.onload = () => { document.getElementById('avatar-fallback').style.display = 'none'; img.style.display = ''; };
    img.onerror = () => { img.style.display = 'none'; };
    img.src = user.avatar;
  } else {
    img.style.display = 'none';
    document.getElementById('avatar-fallback').style.display = '';
  }

  const badge = document.getElementById('provider-badge');
  badge.textContent = PROVIDER_LABELS[user.provider] || user.provider;
  badge.className = `badge badge-${user.provider}`;

  // Сохраняем в историю
  saveSession(user.provider, { name, email: user.email, avatar: user.avatar, userId: user.userId });

  // Показываем таймер и обновляем кнопку выхода
  document.querySelector('.session-row').style.display = 'flex';
  updateLogoutButton(user.provider, true);

  renderSidebar();
  startCountdown();
  show('user-section');
}

// ── RENDER HISTORICAL PROFILE (из localStorage, без активной сессии) ─────────
function showProfileFromSidebar(provider) {
  const s = getSessions();
  const sess = s[provider];
  if (!sess) {
    showToast('Нет сохранённых данных об этом аккаунте');
    return;
  }

  currentViewProvider = provider;

  const name = sess.name || 'Пользователь';
  document.getElementById('user-name').textContent = name;
  document.getElementById('user-email').textContent = sess.email || 'Email не указан';
  document.getElementById('user-email-detail').textContent = sess.email || '—';
  document.getElementById('user-id').textContent = sess.userId || `${provider}_${sess.ts}`;
  document.getElementById('user-provider').textContent = PROVIDER_LABELS[provider] || provider;

  const badge = document.getElementById('provider-badge');
  badge.textContent = PROVIDER_LABELS[provider] || provider;
  badge.className = `badge badge-${provider}`;

  const fallback = document.getElementById('avatar-fallback');
  const img = document.getElementById('avatar-img');
  if (sess.avatar) {
    img.onload = () => { fallback.style.display = 'none'; img.style.display = ''; };
    img.onerror = () => { img.style.display = 'none'; };
    img.src = sess.avatar;
  } else {
    img.style.display = 'none';
    fallback.textContent = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) || '?';
    fallback.style.display = '';
  }

  // Скрываем таймер сессии — это исторический профиль, не активная сессия
  document.querySelector('.session-row').style.display = 'none';

  // Обновляем кнопку: если это не активный провайдер — предлагаем вернуться
  const isActive = (provider === activeProvider);
  updateLogoutButton(activeProvider, isActive);

  show('user-section');
}

// ── UPDATE LOGOUT BUTTON ─────────────────────────────────────────────────────
function updateLogoutButton(provider, isActiveView) {
  const btn = document.getElementById('btn-logout');
  if (!btn) return;

  if (isActiveView) {
    // Просматриваем активный профиль — кнопка "Выйти"
    btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16,17 21,12 16,7"/><line x1="21" y1="12" x2="9" y2="12"/></svg> Выйти из ${PROVIDER_LABELS[provider] || provider}`;
    btn.onclick = logout;
  } else {
    // Просматриваем исторический профиль — кнопка "Назад к активной сессии"
    btn.innerHTML = `← Вернуться к ${PROVIDER_LABELS[provider] || provider}`;
    btn.onclick = () => {
      if (activeProvider && getToken()) {
        fetchMe().then(u => {
          if (u) renderUser(u);
          else { clearToken(); show('login-section'); renderSidebar(); showToast('Сессия истекла'); }
        });
      } else {
        show('login-section');
        renderSidebar();
      }
    };
  }
}

// ── COUNTDOWN ─────────────────────────────────────────────────────────────────
let _cd = null;
function startCountdown() {
  stopCountdown();
  const el = document.getElementById('session-countdown');
  if (!el) return;

  const tick = () => {
    const elapsed = _issuedAt ? Math.floor((Date.now() - _issuedAt) / 1000) : TOKEN_TTL;
    const left = Math.max(0, TOKEN_TTL - elapsed);
    el.textContent = `${Math.floor(left / 60).toString().padStart(2, '0')}:${(left % 60).toString().padStart(2, '0')}`;
    el.style.color = left < 120 ? 'var(--err)' : left < 300 ? '#c0392b' : 'var(--ok)';

    if (left === 0 && activeProvider) {
      tryRefresh().then(ok => { if (ok) _issuedAt = Date.now(); });
    }
  };

  tick();
  _cd = setInterval(tick, 1000);
}

function stopCountdown() {
  if (_cd) { clearInterval(_cd); _cd = null; }
}

// ── SIDEBAR ───────────────────────────────────────────────────────────────────
const ICONS = {
  vk: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.579 6.855c.14-.465 0-.806-.662-.806h-2.193c-.558 0-.813.295-.953.619 0 0-1.115 2.719-2.695 4.482-.513.513-.745.675-1.024.675-.14 0-.343-.162-.343-.627V6.855c0-.558-.162-.806-.626-.806H9.642c-.348 0-.557.258-.557.504 0 .528.79.65.871 2.138v3.228c0 .707-.128.836-.406.836-.745 0-2.557-2.731-3.63-5.858C5.715 6.419 5.504 6.05 4.944 6.05H2.75C2.122 6.05 2 6.345 2 6.669c0 .582.745 3.473 3.473 7.299C7.297 16.588 9.909 18 12.279 18c1.442 0 1.62-.325 1.62-.882v-1.97c0-.628.132-.753.576-.753.326 0 .885.163 2.193 1.425 1.494 1.494 1.74 2.18 2.58 2.18h2.193c.627 0 .941-.325.76-.966-.198-.639-.91-1.568-1.86-2.669-.513-.605-1.282-1.257-1.515-1.583-.326-.42-.233-.605 0-.977 0 0 2.681-3.777 2.961-5.059z"/></svg>`,
  yandex: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.32 21h-2.495V13.51H9.21L5.88 21H3.15l3.555-7.88c-1.98-.84-3.03-2.505-3.03-4.74C3.675 5.085 5.88 3 9.45 3H13.32v18zm-2.495-9.495V5.01H9.36c-1.98 0-3.15 1.17-3.15 3.18 0 1.98 1.125 3.315 3.285 3.315h1.33z"/></svg>`,
  mailru: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 13.5L2 7V18h20V7l-10 6.5zM12 11L2 5h20l-10 6z"/></svg>`,
};
const COLORS = { vk: '#4a76a8', yandex: '#e74c3c', mailru: '#5dade2' };
const ORDER = ['vk', 'yandex', 'mailru'];

const timeAgo = ts => {
  const d = Math.floor((Date.now() - ts) / 1000);
  if (d < 60) return 'только что';
  if (d < 3600) return `${Math.floor(d / 60)} мин назад`;
  if (d < 86400) return `${Math.floor(d / 3600)} ч назад`;
  return `${Math.floor(d / 86400)} д назад`;
};

function renderSidebar() {
  const panel = document.getElementById('sidebar-panel');
  if (!panel) return;

  const s = getSessions();
  const count = ORDER.filter(p => s[p]).length;

  panel.innerHTML = `<div class="sb-header"><span class="sb-title">История входов</span><span class="sb-hint">1 · 2 · 3</span></div>
    <div class="sb-list">${ORDER.map((p, i) => {
      const sess = s[p], c = COLORS[p];
      const isActive = activeProvider === p;
      const isViewing = currentViewProvider === p;
      return `<div class="sb-item${sess ? ' connected' : ''}${isActive ? ' active' : ''}${isViewing ? ' viewing' : ''}" data-p="${p}"${sess ? ' data-connected="true"' : ''}>
        <div class="sb-icon" style="--c:${c}">${ICONS[p]}${sess ? '<span class="sb-dot"></span>' : ''}</div>
        <div class="sb-info"><div class="sb-name">${PROVIDER_LABELS[p]}</div>
          <div class="sb-sub" style="color:${isActive ? 'var(--ok)' : sess ? 'var(--muted)' : 'var(--muted2)'}">${isActive ? '● активная сессия' : sess ? timeAgo(sess.ts) : `клавиша ${i + 1}`}</div>
        </div>
        ${sess && sess.avatar ? `<img class="sb-av" src="${sess.avatar}" onerror="this.style.display='none'" alt="">`
          : sess ? `<div class="sb-av sb-av-init" style="background:${c}18;color:${c}">${(sess.name || '?')[0].toUpperCase()}</div>`
          : `<div class="sb-arrow" style="color:${c}">→</div>`}
      </div>`;
    }).join('')}</div>
    <div class="sb-footer">
      <div class="sb-footer-text">${count} из 3 в истории</div>
      <div class="sb-bar">${ORDER.map(p => `<div class="sb-seg${s[p] ? ' on' : ''}" style="--c:${COLORS[p]}"></div>`).join('')}</div>
    </div>`;

  panel.querySelectorAll('.sb-item').forEach(el => {
    el.addEventListener('click', () => {
      const p = el.dataset.p;
      if (el.dataset.connected === 'true') {
        showProfileFromSidebar(p);
      } else {
        const id = { vk: 'btn-vk', yandex: 'btn-ya', mailru: 'btn-mail' }[p];
        const btn = document.getElementById(id);
        if (btn && !btn.disabled) login(p);
      }
    });
  });
}

// ── KEYBOARD ─────────────────────────────────────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT') return;
  const map = { '1': 'vk', '2': 'yandex', '3': 'mailru' };
  if (map[e.key] && document.getElementById('login-section').style.display !== 'none') login(map[e.key]);
  if (e.key === 'Escape' && document.getElementById('user-section').style.display !== 'none') {
    // Если просматриваем исторический профиль — Esc возвращает к активному
    if (currentViewProvider && currentViewProvider !== activeProvider && activeProvider) {
      fetchMe().then(u => { if (u) renderUser(u); });
    } else {
      logout();
    }
  }
});

// ── CHECK AUTH ───────────────────────────────────────────────────────────────
async function checkAuth() {
  const wt = setTimeout(() => setLoadingMsg('Сервер просыпается... ~30 сек'), 4000);
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

// ── INIT ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-vk')?.addEventListener('click', () => login('vk'));
  document.getElementById('btn-ya')?.addEventListener('click', () => login('yandex'));
  document.getElementById('btn-mail')?.addEventListener('click', () => login('mailru'));

  // Навешиваем обработчик на logout кнопку (будет обновлён в renderUser)
  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) logoutBtn.addEventListener('click', logout);

  renderSidebar();

  const qp = new URLSearchParams(window.location.search);
  const hp = new URLSearchParams(window.location.hash.slice(1));
  history.replaceState(null, '', window.location.pathname);

  const token = qp.get('vk_token') || qp.get('ya_token') || qp.get('mr_token') || qp.get('token') || hp.get('token');
  const error = hp.get('error') || qp.get('error') || qp.get('auth_error');

  if (error) {
    const detail = qp.get('detail');
    const msg = ERROR_LABELS[error] || `Ошибка: ${error}`;
    showToast(detail ? `${msg}: ${detail}` : msg);
    show('login-section');
    renderSidebar();
    return;
  }

  if (token) {
    setToken(token);
    setLoadingMsg('Загружаем профиль...');

    async function loadProfileWithRetry(attempts = 3) {
      for (let i = 0; i < attempts; i++) {
        if (i > 0) {
          setLoadingMsg(`Повторная попытка ${i}/${attempts - 1}...`);
          await new Promise(r => setTimeout(r, 2000));
        }
        const u = await fetchMe();
        if (u) { renderUser(u); renderSidebar(); return; }
      }
      clearToken();
      show('login-section');
      renderSidebar();
      showToast('Не удалось загрузить профиль. Попробуйте войти снова.');
    }

    loadProfileWithRetry();
    return;
  }

  checkAuth();
});
