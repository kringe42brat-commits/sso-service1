// ─── SSO Service Frontend ────────────────────────────────────────────────────
// Токен хранится ТОЛЬКО в памяти — не в localStorage, не в cookie
// При обновлении страницы восстанавливается через refresh cookie (httpOnly)

const PROVIDER_LABELS = { vk: 'VK ID', yandex: 'Яндекс ID', mailru: 'Mail.ru' };
const ERROR_LABELS = {
  vk_auth_failed:     'Ошибка авторизации через VK',
  yandex_auth_failed: 'Ошибка авторизации через Яндекс',
  mailru_auth_failed: 'Ошибка авторизации через Mail.ru',
  invalid_code:       'Недействительный код авторизации',
  invalid_state:      'Ошибка безопасности — попробуйте снова',
};

// ─── IN-MEMORY токен (теряется при F5, но восстанавливается через refresh) ───
let _accessToken = null;
const getToken  = ()      => _accessToken;
const setToken  = (t)     => { _accessToken = t; };
const clearToken = ()     => { _accessToken = null; };

// ─── FETCH HELPERS ────────────────────────────────────────────────────────────
async function apiFetch(url, opts = {}, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const tid  = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...opts,
      credentials: 'include',
      signal:       ctrl.signal,
      headers: {
        ...(opts.headers || {}),
        'X-Requested-With': 'XMLHttpRequest',
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      },
    });
    return res;
  } finally {
    clearTimeout(tid); // FIX: всегда чистим таймаут
  }
}

// ─── UI helpers ───────────────────────────────────────────────────────────────
function show(id) {
  ['loading-screen', 'login-section', 'user-section'].forEach(s => {
    document.getElementById(s).style.display = (s === id) ? '' : 'none';
  });
}

function showToast(msg, isError = true) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className   = 'toast show' + (isError ? '' : ' toast-ok');
  setTimeout(() => t.classList.remove('show'), 4500);
}

const PROVIDER_MAP = { vk: 'vk', yandex: 'ya', mailru: 'mail' };

function setButtonLoading(provider, on) {
  const key   = PROVIDER_MAP[provider];
  const btn   = document.getElementById(`btn-${key}`);
  const arrow = document.getElementById(`arrow-${key}`);
  if (!btn) return;
  btn.disabled = on;
  arrow.innerHTML = on
    ? '<span class="spinner-inline"></span>'
    : '→';
  if (on) {
    document.body.className = provider === 'yandex' ? 'glow-ya' : provider === 'mailru' ? 'glow-mail' : '';
  }
}

// ─── LOGIN ────────────────────────────────────────────────────────────────────
async function login(provider) {
  setButtonLoading(provider, true);
  try {
    const res = await apiFetch(`/auth/${provider}`, { method: 'GET' }, 20000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    window.location.href = data.authUrl;
  } catch (err) {
    setButtonLoading(provider, false);
    document.body.className = '';
    if (err.name === 'AbortError') {
      showToast('Сервер не отвечает. Подождите 10 секунд и попробуйте снова.');
    } else {
      showToast('Ошибка соединения с сервером');
    }
  }
}

// ─── FETCH ME ─────────────────────────────────────────────────────────────────
async function fetchMe() {
  if (!getToken()) return null;
  try {
    const res = await apiFetch('/auth/me');
    if (res.ok) return res.json();
    if (res.status === 401) return null;
    return null;
  } catch { return null; }
}

// ─── TRY REFRESH ──────────────────────────────────────────────────────────────
async function tryRefresh() {
  try {
    const res = await apiFetch('/auth/refresh', { method: 'POST' }, 10000);
    if (!res.ok) return false;
    const { accessToken } = await res.json();
    setToken(accessToken);
    return true;
  } catch { return false; }
}

// ─── CHECK AUTH ───────────────────────────────────────────────────────────────
async function checkAuth() {
  if (getToken()) {
    const user = await fetchMe();
    if (user) { renderUser(user); return; }
    clearToken();
  }
  // Пробуем restore через refresh cookie
  const refreshed = await tryRefresh();
  if (refreshed) {
    const user = await fetchMe();
    if (user) { renderUser(user); return; }
  }
  show('login-section');
}

// ─── RENDER USER ──────────────────────────────────────────────────────────────
function renderUser(user) {
  const name     = user.name    || user.userId;
  const initials = (name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2)) || '?';

  document.getElementById('user-name').textContent          = name;
  document.getElementById('user-email').textContent         = user.email || 'Email не указан';
  document.getElementById('user-id').textContent            = user.userId;
  document.getElementById('user-email-detail').textContent  = user.email || '—';
  document.getElementById('user-provider').textContent      = PROVIDER_LABELS[user.provider] || user.provider;
  document.getElementById('avatar-fallback').textContent    = initials;

  if (user.avatar) {
    const img  = document.getElementById('avatar-img');
    img.onload  = () => { document.getElementById('avatar-fallback').style.display = 'none'; img.style.display = ''; };
    img.onerror = () => { img.style.display = 'none'; document.getElementById('avatar-fallback').style.display = ''; };
    img.src = user.avatar;
  }

  const badge = document.getElementById('provider-badge');
  badge.textContent = PROVIDER_LABELS[user.provider] || user.provider;
  badge.className   = `badge badge-${user.provider}`;

  document.body.className = user.provider === 'yandex' ? 'glow-ya' : user.provider === 'mailru' ? 'glow-mail' : '';
  show('user-section');
}

// ─── LOGOUT ───────────────────────────────────────────────────────────────────
async function logout() {
  try {
    await apiFetch('/auth/logout', { method: 'POST' });
  } catch { /* ignore */ }
  clearToken();
  document.body.className = '';
  show('login-section');
}

// ─── INIT ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  // Читаем ошибку или токен из fragment (#), а не из query string
  const hash  = window.location.hash.slice(1);
  const params = new URLSearchParams(hash);
  // Убираем fragment из URL сразу
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
    const user = await fetchMe();
    if (user) { renderUser(user); return; }
    clearToken();
    show('login-section');
    return;
  }

  await checkAuth();
});

// Кнопки — через addEventListener, без onclick в HTML
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-vk')?.addEventListener('click',  () => login('vk'));
  document.getElementById('btn-ya')?.addEventListener('click',  () => login('yandex'));
  document.getElementById('btn-mail')?.addEventListener('click',() => login('mailru'));
  document.getElementById('btn-logout')?.addEventListener('click', logout);
});
