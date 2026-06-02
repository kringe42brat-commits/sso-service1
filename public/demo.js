'use strict';

// ── HELPERS ──────────────────────────────────

function showState(id) {
  ['state-loading','state-login','state-user'].forEach(s => {
    const el = document.getElementById(s);
    if (el) el.style.display = s === id ? 'block' : 'none';
  });
}

function toast(msg) {
  const t = document.getElementById('demo-toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

// Cookie helpers
function getCookie(name) {
  const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}
function setCookie(name, value, days) {
  const exp = new Date(Date.now() + days * 864e5).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value)};expires=${exp};path=/;SameSite=Lax`;
}
function deleteCookie(name) {
  document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
}

const PROVIDER_LABELS = { vk:'VK ID', yandex:'Яндекс', mailru:'Mail.ru' };
const PROVIDER_COLORS = { vk:'#0077ff', yandex:'#fc3f1d', mailru:'#168de2' };

// ── RENDER USER ──────────────────────────────
function renderUser(user, accessToken) {
  const name     = user.name || user.userId || 'Пользователь';
  const initials = name.split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2) || '?';
  const provLabel = PROVIDER_LABELS[user.provider] || user.provider;
  const provColor = PROVIDER_COLORS[user.provider] || '#666';

  document.getElementById('demo-name').textContent    = name;
  document.getElementById('demo-email').textContent   = user.email || 'Email не указан';
  document.getElementById('demo-email2').textContent  = user.email || '—';
  document.getElementById('demo-uid').textContent     = user.userId;
  document.getElementById('demo-provider').textContent= provLabel;

  // Badge
  const badge = document.getElementById('demo-badge');
  badge.textContent = provLabel;
  badge.style.background = provColor + '18';
  badge.style.color       = provColor;
  badge.style.border      = `1px solid ${provColor}40`;

  // Avatar
  const fallback = document.getElementById('demo-avatar-fallback');
  const img = document.getElementById('demo-avatar');
  
  if (user.avatar) {
    img.onload  = () => { fallback.style.display='none'; img.style.display='block'; };
    img.onerror = () => { fallback.style.display='flex'; img.style.display='none'; fallback.textContent = initials; };
    img.src = user.avatar;
  } else {
    fallback.style.display = 'flex';
    img.style.display = 'none';
    fallback.textContent = initials;
  }

  showState('state-user');
}

// ── AUTH FLOW ─────────────────────────────────

async function tryAuth() {
  showState('state-loading');

  // Шаг 1: проверяем сохранённый токен в cookie
  let accessToken = getCookie('demo_access_token');

  if (accessToken) {
    const user = await fetchMe(accessToken);
    if (user) { renderUser(user, accessToken); return; }
    // Токен протух — удаляем
    deleteCookie('demo_access_token');
    accessToken = null;
  }

  // Шаг 2: пробуем refresh (общий SSO cookie на том же домене)
  try {
    const res = await fetch('/auth/refresh', {
      method:'POST',
      credentials:'include',
      headers:{ 'X-Requested-With':'XMLHttpRequest' },
    });
    if (res.ok) {
      const { accessToken: newToken } = await res.json();
      const user = await fetchMe(newToken);
      if (user) {
        setCookie('demo_access_token', newToken, 1/96); // 15 минут
        renderUser(user, newToken);
        return;
      }
    }
  } catch {}

  // Шаг 3: не авторизован — показываем кнопку входа
  showState('state-login');
}

async function fetchMe(token) {
  try {
    const res = await fetch('/auth/me', {
      credentials:'include',
      headers:{ 
        Authorization:`Bearer ${token}`, 
        'X-Requested-With':'XMLHttpRequest' 
      },
    });
    return res.ok ? res.json() : null;
  } catch { return null; }
}

async function logout() {
  const token = getCookie('demo_access_token');
  if (token) {
    try {
      await fetch('/auth/logout', {
        method:'POST', 
        credentials:'include',
        headers:{ 
          Authorization:`Bearer ${token}`, 
          'X-Requested-With':'XMLHttpRequest' 
        },
      });
    } catch {}
  }
  deleteCookie('demo_access_token');
  showState('state-login');
  toast('Вы вышли из аккаунта');
}

// ── INIT ─────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Кнопка "Войти через SSO" — ведёт на основной сайт
  document.getElementById('btn-login-sso')?.addEventListener('click', (e) => {
    e.preventDefault();
    // Запоминаем откуда пришли, чтобы вернуться
    sessionStorage.setItem('sso_return_url', window.location.href);
    window.location.href = '/';
  });

  // Кнопка выхода
  document.getElementById('btn-demo-logout')?.addEventListener('click', logout);

  // Если вернулись с SSO с токеном в URL
  const qp = new URLSearchParams(window.location.search);
  const urlToken = qp.get('vk_token') || qp.get('ya_token') || qp.get('mr_token') || qp.get('token');
  
  if (urlToken) {
    // Убираем токен из URL
    history.replaceState(null, '', window.location.pathname);
    // Сохраняем в cookie
    setCookie('demo_access_token', urlToken, 1/96);
    // Проверяем токен и показываем профиль
    tryAuth();
    return;
  }

  // Обычная загрузка — проверяем cookie
  tryAuth();
});