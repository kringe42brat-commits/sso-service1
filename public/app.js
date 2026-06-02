'use strict';

const PROVIDER_LABELS = { vk:'VK ID', yandex:'Яндекс', mailru:'Mail.ru' };
const PROVIDER_ICONS = { vk:'🔷', yandex:'🔴', mailru:'📧' };
const ERROR_LABELS = {
  vk_auth_failed:'Ошибка авторизации VK',
  yandex_auth_failed:'Ошибка авторизации Яндекс',
  mailru_auth_failed:'Ошибка авторизации Mail.ru',
  invalid_code:'Недействительный код',
  invalid_state:'Ошибка безопасности — попробуйте снова',
};

// ── PER-PROVIDER SESSIONS ──────────────────────
const SK = 'sso_sessions_v7';

function getAllSessions() {
  try { return JSON.parse(localStorage.getItem(SK) || '{}'); }
  catch { return {}; }
}
function saveSession(provider, data) {
  const s = getAllSessions();
  s[provider] = { ...data, ts: Date.now() };
  localStorage.setItem(SK, JSON.stringify(s));
}
function removeSession(provider) {
  const s = getAllSessions();
  delete s[provider];
  localStorage.setItem(SK, JSON.stringify(s));
}
function getSession(provider) {
  return getAllSessions()[provider] || null;
}
function hasAnySession() {
  return Object.keys(getAllSessions()).length > 0;
}
function getActiveProvider() {
  const s = getAllSessions();
  const keys = Object.keys(s);
  return keys.length > 0 ? keys[0] : null;
}

// ── FETCH ────────────────────────────────────
async function apiFetch(url, opts={}, ms=30000) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...opts, credentials:'include', signal:ctrl.signal,
      headers: {
        ...(opts.headers||{}),
        'X-Requested-With':'XMLHttpRequest',
      },
    });
  } finally { clearTimeout(tid); }
}

// ── UI ───────────────────────────────────────
function show(id) {
  const sections = ['loading-screen', 'login-section', 'user-section'];
  sections.forEach(s => {
    const el = document.getElementById(s);
    if (el) {
      if (s === 'loading-screen') {
        el.style.display = s === id ? 'flex' : 'none';
      } else {
        el.style.display = s === id ? 'block' : 'none';
      }
    }
  });
}

function setLoadingMsg(msg) {
  const el = document.getElementById('loading-text');
  if (el) el.textContent = msg;
}

function showToast(msg, type='') {
  const t = document.getElementById('toast');
  if (!t) { alert(msg); return; }
  t.textContent = msg;
  t.className = `toast show${type ? ' toast-'+type : ''}`;
  setTimeout(() => t.classList.remove('show'), 4500);
}

const PM = {vk:'vk', yandex:'ya', mailru:'mail'};
function setButtonLoading(p, on) {
  const btn   = document.getElementById(`btn-${PM[p]}`);
  const arrow = document.getElementById(`arrow-${PM[p]}`);
  if (!btn) { console.warn(`[UI] Кнопка btn-${PM[p]} не найдена`); return; }
  btn.disabled = on;
  if (arrow) arrow.innerHTML = on ? '<span class="spinner-inline"></span>' : '→';
}

// ── LOGIN ─────────────────────────────────────
async function login(p) {
  console.log(`[LOGIN] Starting login for ${p}`);
  sessionStorage.removeItem('sso_pending_provider');
  sessionStorage.setItem('sso_pending_provider', p);

  setButtonLoading(p, true);
  try {
    const res = await apiFetch(`/auth/${p}`, {}, 60000);
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`HTTP ${res.status}: ${errText}`);
    }
    const { authUrl } = await res.json();
    if (!authUrl) throw new Error('Сервер вернул пустой authUrl');
    console.log(`[LOGIN] Got authUrl, redirecting...`);
    window.location.href = authUrl;
  } catch(e) {
    console.error(`[LOGIN] Error:`, e);
    setButtonLoading(p, false);
    const msg = e.name === 'AbortError'
      ? 'Сервер не отвечает (возможно, он спит на Render). Подождите ~30-60 сек и попробуйте снова.'
      : 'Ошибка соединения: ' + e.message;
    showToast(msg, 'err');
    alert(msg);
  }
}

// ── FETCH ME ─────────────────────────────────
async function fetchMe(token) {
  try {
    const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
    console.log(`[FETCHME] Calling /auth/me`);
    const r = await apiFetch('/auth/me', { headers }, 20000);
    console.log(`[FETCHME] Response status: ${r.status}`);
    if (!r.ok) {
      const errText = await r.text();
      console.log(`[FETCHME] Error response: ${errText}`);
      return null;
    }
    const data = await r.json();
    console.log(`[FETCHME] Success:`, data);
    return data;
  } catch(e) {
    console.error(`[FETCHME] Error:`, e);
    return null;
  }
}

// ── REFRESH ───────────────────────────────────
async function tryRefresh(provider) {
  try {
    console.log(`[REFRESH] Trying refresh for ${provider}`);
    const r = await apiFetch('/auth/refresh', {method:'POST'}, 20000);
    console.log(`[REFRESH] Response status: ${r.status}`);
    if (!r.ok) {
      const errText = await r.text();
      console.log(`[REFRESH] Error: ${errText}`);
      return false;
    }
    const { accessToken } = await r.json();
    console.log(`[REFRESH] Got new token for ${provider}`);
    const s = getAllSessions();
    if (s[provider]) {
      s[provider].token = accessToken;
      s[provider].ts = Date.now();
      localStorage.setItem(SK, JSON.stringify(s));
    }
    return true;
  } catch(e) {
    console.error(`[REFRESH] Error:`, e);
    return false;
  }
}

// ── LOGOUT SPECIFIC PROVIDER ─────────────────
async function logoutProvider(provider) {
  console.log(`[LOGOUT] Logging out from ${provider}`);
  const sess = getSession(provider);

  try { 
    console.log(`[LOGOUT] Sending logout request`);
    const headers = (sess && sess.token) ? { 'Authorization': `Bearer ${sess.token}` } : {};
    const r = await apiFetch('/auth/logout', {
      method:'POST',
      headers: headers
    }, 8000); 
    console.log(`[LOGOUT] Server response: ${r.status}`);
    const respText = await r.text();
    console.log(`[LOGOUT] Response body:`, respText);
  } catch(e) {
    console.error(`[LOGOUT] Server logout error:`, e);
  }

  console.log(`[LOGOUT] Clearing client session for ${provider}`);
  removeSession(provider);
  stopCountdown();

  const remaining = getAllSessions();
  const remainingProviders = Object.keys(remaining);

  if (remainingProviders.length > 0) {
    const nextProvider = remainingProviders[0];
    console.log(`[LOGOUT] Switching to ${nextProvider}`);
    renderUserFromSession(nextProvider);
    showToast(`Вышли из ${PROVIDER_LABELS[provider]}`, 'ok');
  } else {
    console.log(`[LOGOUT] No remaining sessions, showing login`);
    renderSidebar();
    show('login-section');
    showToast(`Вышли из ${PROVIDER_LABELS[provider]}`, 'ok');
  }
}

// ── RENDER USER FROM SESSION ──────────────────
function renderUserFromSession(provider) {
  console.log('[RENDER] provider =', provider);
  console.log('[RENDER] session =', getSession(provider));

  const userSection = document.getElementById('user-section');
  console.log('[RENDER] user-section =', userSection);

  const sess = getSession(provider);
  if (!sess) {
    console.log(`[RENDER] No session for ${provider}, showing login`);
    show('login-section');
    return;
  }

  const name = sess.name || sess.userId || 'Пользователь';

  document.getElementById('user-name').textContent = name;
  document.getElementById('user-email-detail').textContent = sess.email || '—';
  document.getElementById('user-id').textContent = sess.userId || '—';
  document.getElementById('user-provider').textContent =
    PROVIDER_LABELS[provider] || provider;
  document.getElementById('provider-badge').textContent =
    PROVIDER_LABELS[provider] || provider;

  const logoutBtn = document.getElementById('btn-logout');
  logoutBtn.onclick = () => logoutProvider(provider);

  const logoutLabel = document.querySelector('.logout-label');
  if (logoutLabel) {
    logoutLabel.textContent =
      `Выйти из ${PROVIDER_LABELS[provider]}`;
  }

  // ── АВАТАРКА ───────────────────────────────
  const avatarImg = document.getElementById('avatar-img');
  const avatarFallback = document.getElementById('avatar-fallback');

  if (sess.avatar && avatarImg && avatarFallback) {
    avatarImg.src = sess.avatar;
    avatarImg.style.display = 'block';
    avatarFallback.style.display = 'none';
  } else if (avatarImg && avatarFallback) {
    avatarImg.style.display = 'none';
    avatarFallback.style.display = 'flex';
    avatarFallback.textContent = (sess.name || '?')[0].toUpperCase();
  }

  startCountdown(provider);
  show('user-section');
  renderSidebar();
}

// ── COUNTDOWN ────────────────────────────────
let _cd = null;
function startCountdown(provider) {
  stopCountdown();
  const sess = getSession(provider);
  if (!sess) return;

  const el = document.getElementById('session-countdown');
  if (!el) return;

  const TTL = 15 * 60;
  const issuedAt = sess.ts || Date.now();

  const tick = () => {
    const elapsed = Math.floor((Date.now() - issuedAt) / 1000);
    const left = Math.max(0, TTL - elapsed);
    const m = Math.floor(left/60).toString().padStart(2,'0');
    const s = (left%60).toString().padStart(2,'0');
    el.textContent = `${m}:${s}`;
    el.style.color = left<<120 ? 'var(--err)' : left<<300 ? '#d29922' : 'var(--ok)';
    if (left === 0) {
      tryRefresh(provider).then(ok => { 
        if (ok) { 
          const s = getAllSessions();
          if (s[provider]) { s[provider].ts = Date.now(); localStorage.setItem(SK, JSON.stringify(s)); }
        }
      });
    }
  };
  tick();
  _cd = setInterval(tick, 1000);
}
function stopCountdown() { if(_cd){clearInterval(_cd);_cd=null;} }

// ── SIDEBAR ───────────────────────────────────
const ICONS = {
  vk:`<<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.579 6.855c.14-.465 0-.806-.662-.806h-2.193c-.558 0-.813.295-.953.619 0 0-1.115 2.719-2.695 4.482-.513.513-.745.675-1.024.675-.14 0-.343-.162-.343-.627V6.855c0-.558-.162-.806-.626-.806H9.642c-.348 0-.557.258-.557.504 0 .528.79.65.871 2.138v3.228c0 .707-.128.836-.406.836-.745 0-2.557-2.731-3.63-5.858C5.715 6.419 5.504 6.05 4.944 6.05H2.75C2.122 6.05 2 6.345 2 6.669c0 .582.745 3.473 3.473 7.299C7.297 16.588 9.909 18 12.279 18c1.442 0 1.62-.325 1.62-.882v-1.97c0-.628.132-.753.576-.753.326 0 .885.163 2.193 1.425 1.494 1.494 1.74 2.18 2.58 2.18h2.193c.627 0 .941-.325.76-.966-.198-.639-.91-1.568-1.86-2.669-.513-.605-1.282-1.257-1.515-1.583-.326-.42-.233-.605 0-.977 0 0 2.681-3.777 2.961-5.059z"/></svg>`,
  yandex:`<<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.32 21h-2.495V13.51H9.21L5.88 21H3.15l3.555-7.88c-1.98-.84-3.03-2.505-3.03-4.74C3.675 5.085 5.88 3 9.45 3H13.32v18zm-2.495-9.495V5.01H9.36c-1.98 0-3.15 1.17-3.15 3.18 0 1.98 1.125 3.315 3.285 3.315h1.33z"/></svg>`,
  mailru:`<<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 13.5L2 7V18h20V7l-10 6.5zM12 11L2 5h20l-10 6z"/></svg>`,
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
  const s = getAllSessions();
  const activeProvider = getActiveProvider();
  const count = ORDER.filter(p => s[p]).length;

  panel.innerHTML = `
    <div class="sb-header">
      <span class="sb-title">Мои аккаунты</span>
      <span class="sb-hint">${count}/3</span>
    </div>
    <div class="sb-list">
      ${ORDER.map((p,i) => {
        const sess = s[p], c = COLORS[p];
        const isActive = p === activeProvider;
        const isConnected = !!sess;
        return `<div class="sb-item${isConnected?' connected':''}${isActive?' active':''}" data-p="${p}" style="--c:${c}">
          <div class="sb-icon" style="--c:${c}">${ICONS[p]}${sess?'<span class="sb-dot"></span>':''}</div>
          <div class="sb-info">
            <div class="sb-name">${PROVIDER_LABELS[p]}</div>
            <div class="sb-sub" style="color:${sess?'var(--ok)':'var(--muted2)'}">${sess?(sess.name || 'Подключён'):'не подключён'}</div>
          </div>
          ${sess
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
      const sess = getSession(p);
      if (sess) {
        renderUserFromSession(p);
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

  if (map[e.key]) {
    const p = map[e.key];
    const sess = getSession(p);
    if (sess) {
      renderUserFromSession(p);
    } else if (document.getElementById('login-section').style.display !== 'none') {
      login(p);
    }
  }

  if (e.key === 'Escape' && document.getElementById('user-section').style.display !== 'none') {
    const active = getActiveProvider();
    if (active) logoutProvider(active);
  }
});

// ── HANDLE OAUTH CALLBACK ────────────────────
async function handleOAuthCallback() {
  const qp = new URLSearchParams(window.location.search);

  const token =
    qp.get('vk_token') ||
    qp.get('ya_token') ||
    qp.get('mr_token') ||
    qp.get('token');

  const error = qp.get('error') || qp.get('auth_error');
  console.log(`[OAUTH] Checking URL params. Token present: ${!!token}, Error: ${error || 'none'}`);

  if (error) {
    showToast(ERROR_LABELS[error] || `Ошибка: ${error}`, 'err');
    history.replaceState(null, '', window.location.pathname);
    show('login-section');
    return false;
  }

  if (!token) {
    console.log(`[OAUTH] No token in URL`);
    return false;
  }

let provider = null;

if (qp.get('vk_token')) provider = 'vk';
else if (qp.get('ya_token')) provider = 'yandex';
else if (qp.get('mr_token')) provider = 'mailru';
else if (qp.get('token')) provider = 'vk'; // временно для VK

  if (!provider) {
    showToast('Неизвестный провайдер', 'err');
    show('login-section');
    return false;
  }

  console.log(`[OAUTH] Got token for ${provider}`);

  history.replaceState(null, '', window.location.pathname);

  setLoadingMsg('Загружаем профиль...');
  show('loading-screen');

  for (let i = 0; i < 3; i++) {
    if (i > 0) { 
      setLoadingMsg(`Повтор ${i}...`); 
      await new Promise(r => setTimeout(r, 1500)); 
    }

    console.log(`[OAUTH] Attempt ${i+1} to fetch user data`);
    const userData = await fetchMe(token);
    if (userData) {
      console.log(`[OAUTH] Got user data:`, userData);

     const actualProvider = userData.provider;

// В handleOAuthCallback и checkAuth, внутри saveSession:
saveSession(actualProvider, {
  token: token,
  name: userData.name || userData.userId,
  userId: userData.userId,
  provider: actualProvider,
  email: userData.email || null,
  avatar: userData.avatar || null,  // ← добавь это
  ts: Date.now()
});

renderUserFromSession(actualProvider);

      console.log(`[OAUTH] Session saved for ${provider}`);
      renderUserFromSession(provider);
      showToast(`Вход через ${PROVIDER_LABELS[provider]} выполнен`, 'ok');
      return true;
    }

    console.log(`[OAUTH] Attempt ${i+1} failed`);
  }

  console.log(`[OAUTH] All attempts failed`);
  showToast('Не удалось загрузить профиль. Попробуйте войти снова.', 'err');
  show('login-section');
  return false;
}

// ── CHECK AUTH ON LOAD ───────────────────────
async function checkAuth() {
  console.log(`[INIT] Checking auth state...`);

  const handled = await handleOAuthCallback();
  if (handled) {
    console.log(`[INIT] OAuth callback handled successfully`);
    return;
  }

  const wt = setTimeout(() => setLoadingMsg('Сервер запускается, подождите...'), 4000);

  try {
    const sessions = getAllSessions();
    const providers = Object.keys(sessions);
    console.log(`[INIT] Found sessions:`, providers);

    if (providers.length > 0) {
      for (const provider of providers) {
        console.log(`[INIT] Trying refresh for ${provider}`);
        const ok = await tryRefresh(provider);
        if (ok) {
          console.log(`[INIT] Refresh successful for ${provider}`);
          const sess = getSession(provider);
          if (sess) {
            const userData = await fetchMe(sess.token);
            if (userData) {
              saveSession(provider, {
                token: sess.token,
                name: userData.name || userData.userId,
                userId: userData.userId,
                provider: userData.provider,
                email: userData.email || null,
                ts: Date.now()
              });

              clearTimeout(wt);
              renderUserFromSession(provider);
              return;
            }
          }
        } else {
          console.log(`[INIT] Refresh failed for ${provider}, removing session`);
          removeSession(provider);
        }
      }
    }
  } catch (e) {
    console.error(`[INIT] Auth check error:`, e);
  }

  clearTimeout(wt);

  const sessions = getAllSessions();
  if (Object.keys(sessions).length > 0) {
    const first = Object.keys(sessions)[0];
    console.log(`[INIT] Showing first available session: ${first}`);
    renderUserFromSession(first);
  } else {
    console.log(`[INIT] No sessions, showing login`);
    show('login-section');
  }
}

// ── INIT ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  console.log(`[INIT] DOM loaded, initializing app`);

  document.getElementById('btn-vk')?.addEventListener('click',   () => login('vk'));
  document.getElementById('btn-ya')?.addEventListener('click',   () => login('yandex'));
  document.getElementById('btn-mail')?.addEventListener('click', () => login('mailru'));

  renderSidebar();
  checkAuth();
});