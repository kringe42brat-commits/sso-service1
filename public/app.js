'use strict';

const PROVIDER_LABELS = { vk:'VK ID', yandex:'Яндекс', mailru:'Mail.ru' };
const PROVIDER_COLORS = { vk:'#0077ff', yandex:'#fc3f1d', mailru:'#168de2' };
const ORDER           = ['vk','yandex','mailru'];

const ERROR_LABELS = {
  vk_auth_failed:     'Ошибка авторизации VK',
  yandex_auth_failed: 'Ошибка авторизации Яндекс',
  mailru_auth_failed:  'Ошибка авторизации Mail.ru',
  invalid_code:       'Недействительный код',
  invalid_state:      'Ошибка безопасности — попробуйте снова',
};

// ════════════════════════════════════════════
// ХРАНИЛИЩЕ СЕССИЙ (по одной на провайдер)
// Каждый провайдер независим. Токены в localStorage.
// ════════════════════════════════════════════
const TOKENS_KEY = 'sso_sessions_v2';

function getAllSessions() {
  try { return JSON.parse(localStorage.getItem(TOKENS_KEY) || '{}'); }
  catch { return {}; }
}

function saveSession(provider, token) {
  const user = decodeJwt(token);
  if (!user) return;
  try {
    const all = getAllSessions();
    all[provider] = { token, user, savedAt: Date.now() };
    localStorage.setItem(TOKENS_KEY, JSON.stringify(all));
  } catch (e) {
    console.error('Ошибка сохранения сессии:', e);
  }
}

function removeSession(provider) {
  try {
    const all = getAllSessions();
    delete all[provider];
    localStorage.setItem(TOKENS_KEY, JSON.stringify(all));
  } catch (e) {
    console.error('Ошибка удаления сессии:', e);
  }
}

function getSession(provider) {
  return getAllSessions()[provider] || null;
}

function isExpired(token) {
  const d = decodeJwt(token);
  if (!d || !d.exp) return true;
  return (Date.now() / 1000) > d.exp;
}

// ИСПРАВЛЕННАЯ ФУНКЦИЯ ДЕКОДИРОВАНИЯ
function decodeJwt(token) {
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return null;

    // 1. Конвертируем Base64Url в стандартный Base64
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

    // 2. Возвращаем удалённый "паддинг" (выравниваем длину строки)
    const pad = base64.length % 4;
    if (pad) {
      base64 += '='.repeat(4 - pad);
    }

    // 3. Декодируем строку с поддержкой кириллицы (UTF-8)
    const jsonPayload = decodeURIComponent(
      window.atob(base64)
        .split('')
        .map(function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join('')
    );

    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error('Ошибка декодирования JWT:', e);
    return null; 
  }
}

// ════════════════════════════════════════════
// UI
// ════════════════════════════════════════════
let activeView = null; // какой провайдер сейчас в главной карточке

const DISPLAY = {
  'loading-screen': 'flex',
  'login-section':  'block',
  'user-section':   'block',
};

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

function showToast(msg, type = '') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = `toast show${type ? ' toast-' + type : ''}`;
  setTimeout(() => t.classList.remove('show'), 4000);
}

const PM = { vk:'vk', yandex:'ya', mailru:'mail' };

function setButtonLoading(p, on) {
  const btn   = document.getElementById(`btn-${PM[p]}`);
  const arrow = document.getElementById(`arrow-${PM[p]}`);
  if (!btn) return;
  btn.disabled = on;
  if (arrow) arrow.innerHTML = on ? '<span class="spinner-inline"></span>' : '→';
}

// ════════════════════════════════════════════
// COUNTDOWN — привязан к конкретному токену
// ════════════════════════════════════════════
let _cd = null;

function startCountdown(expTimestamp) {
  stopCountdown();
  const el = document.getElementById('session-countdown');
  if (!el) return;
  const tick = () => {
    const left = Math.max(0, Math.floor((expTimestamp - Date.now()) / 1000));
    const m = Math.floor(left / 60).toString().padStart(2, '0');
    const s = (left % 60).toString().padStart(2, '0');
    el.textContent = `${m}:${s}`;
    el.style.color = left < 120 ? 'var(--err)' : left < 300 ? '#d29922' : 'var(--ok)';
  };
  tick();
  _cd = setInterval(tick, 1000);
}

function stopCountdown() {
  if (_cd) { clearInterval(_cd); _cd = null; }
}

// ════════════════════════════════════════════
// ПОКАЗАТЬ ПРОФИЛЬ КОНКРЕТНОГО ПРОВАЙДЕРА
// ════════════════════════════════════════════
function showProfile(provider, _visited) {
  // Защита от рекурсии: если уже показываем этого провайдера — выходим
  if (activeView === provider) return;
  
  _visited = _visited || new Set();
  if (_visited.has(provider)) {
    // Зациклились — показываем login
    activeView = null;
    stopCountdown();
    show('login-section');
    return;
  }
  _visited.add(provider);

  const sess = getSession(provider);

  // Нет сессии — предлагаем войти
  if (!sess) {
    activeView = null;
    stopCountdown(); // ← ИСПРАВЛЕНО: останавливаем таймер
    show('login-section');
    return;
  }

  // Токен истёк — удаляем, переключаемся
  if (isExpired(sess.token)) {
    removeSession(provider);
    renderSidebar();
    showToast(`Сессия ${PROVIDER_LABELS[provider]} истекла — войдите снова`, 'err');
    const others = ORDER.filter(p => {
      const s = getSession(p);
      return s && !isExpired(s.token);
    });
    if (others.length > 0) { 
      showProfile(others[0], _visited); 
    }
    else { 
      activeView = null; 
      stopCountdown(); // ← ИСПРАВЛЕНО: останавливаем таймер
      show('login-section'); 
    }
    return;
  }

  activeView = provider;
  const user  = sess.user;
  const name  = user.name || user.sub || '—';
  const color = PROVIDER_COLORS[provider] || '#666';
  const initials = name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) || '?';

  // Заполняем поля
  document.getElementById('user-name').textContent          = name;
  document.getElementById('user-email').textContent         = user.email || 'Email не указан';
  document.getElementById('user-id').textContent            = user.sub;
  document.getElementById('user-email-detail').textContent  = user.email || '—';
  document.getElementById('user-provider').textContent      = PROVIDER_LABELS[provider];
  document.getElementById('avatar-fallback').textContent    = initials;
  document.getElementById('avatar-fallback').style.display  = '';

  // Аватар
  const img = document.getElementById('avatar-img');
  img.style.display = 'none';
  if (user.av) {
    img.onload  = () => { document.getElementById('avatar-fallback').style.display = 'none'; img.style.display = ''; };
    img.onerror = () => { img.style.display = 'none'; };
    img.src = user.av;
  }

  // Бейдж
  const badge = document.getElementById('provider-badge');
  badge.textContent          = PROVIDER_LABELS[provider];
  badge.style.background     = color + '18';
  badge.style.color          = color;
  badge.style.border         = `1px solid ${color}40`;

  // Кнопка выхода — показывает из какого аккаунта
  const lbl = document.querySelector('.logout-label');
  if (lbl) lbl.textContent = `Выйти из ${PROVIDER_LABELS[provider]}`;

  // Таймер из exp поля токена
  const decoded = decodeJwt(sess.token);
  if (decoded?.exp) startCountdown(decoded.exp * 1000);

  renderSidebar();
  show('user-section');
}

// ════════════════════════════════════════════
// ВЫХОД ИЗ КОНКРЕТНОГО ПРОВАЙДЕРА
// ════════════════════════════════════════════
async function logoutProvider(provider) {
  const sess = getSession(provider);

  // Отзываем токен на сервере
  if (sess?.token) {
    try {
      await fetch('/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Authorization': `Bearer ${sess.token}`,
          'X-Requested-With': 'XMLHttpRequest',
        },
      });
    } catch { /* игнорируем — всё равно удалим локально */ }
  }

  removeSession(provider);

  // Останавливаем таймер ТОЛЬКО если смотрели именно этот профиль
  if (activeView === provider) {
    stopCountdown();
    const remaining = ORDER.filter(p => {
      const s = getSession(p);
      return s && !isExpired(s.token);
    });
    if (remaining.length > 0) {
      showProfile(remaining[0]);
    } else {
      activeView = null;
      show('login-section');
    }
  }

  renderSidebar();
  showToast(`Вышли из ${PROVIDER_LABELS[provider]}`, 'ok');
}

// ════════════════════════════════════════════
// ЛОГИН (запуск OAuth)
// ════════════════════════════════════════════
async function login(p) {
  setButtonLoading(p, true);
  try {
    const res = await fetch(`/auth/${p}`, {
      credentials: 'include',
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const { authUrl } = await res.json();
    window.location.href = authUrl;
  } catch(e) {
    setButtonLoading(p, false);
    showToast(
      e.name === 'AbortError' ? 'Сервер не отвечает — подождите ~30 сек' : 'Ошибка соединения',
      'err'
    );
  }
}

// ════════════════════════════════════════════
// SIDEBAR
// ════════════════════════════════════════════
const ICONS = {
  vk:     `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.579 6.855c.14-.465 0-.806-.662-.806h-2.193c-.558 0-.813.295-.953.619 0 0-1.115 2.719-2.695 4.482-.513.513-.745.675-1.024.675-.14 0-.343-.162-.343-.627V6.855c0-.558-.162-.806-.626-.806H9.642c-.348 0-.557.258-.557.504 0 .528.79.65.871 2.138v3.228c0 .707-.128.836-.406.836-.745 0-2.557-2.731-3.63-5.858C5.715 6.419 5.504 6.05 4.944 6.05H2.75C2.122 6.05 2 6.345 2 6.669c0 .582.745 3.473 3.473 7.299C7.297 16.588 9.909 18 12.279 18c1.442 0 1.62-.325 1.62-.882v-1.97c0-.628.132-.753.576-.753.326 0 .885.163 2.193 1.425 1.494 1.494 1.74 2.18 2.58 2.18h2.193c.627 0 .941-.325.76-.966-.198-.639-.91-1.568-1.86-2.669-.513-.605-1.282-1.257-1.515-1.583-.326-.42-.233-.605 0-.977 0 0 2.681-3.777 2.961-5.059z"/></svg>`,
  yandex: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.32 21h-2.495V13.51H9.21L5.88 21H3.15l3.555-7.88c-1.98-.84-3.03-2.505-3.03-4.74C3.675 5.085 5.88 3 9.45 3H13.32v18zm-2.495-9.495V5.01H9.36c-1.98 0-3.15 1.17-3.15 3.18 0 1.98 1.125 3.315 3.285 3.315h1.33z"/></svg>`,
  mailru: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 13.5L2 7V18h20V7l-10 6.5zM12 11L2 5h20l-10 6z"/></svg>`,
};

function timeAgo(ts) {
  const d = Math.floor((Date.now() - ts) / 1000);
  if (d < 60)    return 'только что';
  if (d < 3600)  return `${Math.floor(d / 60)} мин назад`;
  if (d < 86400) return `${Math.floor(d / 3600)} ч назад`;
  return `${Math.floor(d / 86400)} д назад`;
}

function renderSidebar() {
  const panel = document.getElementById('sidebar-panel');
  if (!panel) return;

  const all   = getAllSessions();
  const count = ORDER.filter(p => all[p] && !isExpired(all[p].token)).length;

  panel.innerHTML = `
    <div class="sb-header">
      <span class="sb-title">Аккаунты</span>
      <span class="sb-count">${count}/3</span>
    </div>
    <div class="sb-list">
      ${ORDER.map(p => {
        const sess    = all[p];
        const alive   = sess && !isExpired(sess.token);
        const c       = PROVIDER_COLORS[p];
        const isActive = (p === activeView);

        if (alive) {
          const user = sess.user;
          const name = (user.name || user.sub || PROVIDER_LABELS[p]).split(' ')[0];
          return `
            <div class="sb-item sb-connected${isActive ? ' sb-active' : ''}"
                 data-action="view" data-p="${p}"
                 style="--item-color:${c}"
                 title="Просмотреть профиль ${PROVIDER_LABELS[p]}">
              <div class="sb-icon" style="--c:${c}">
                ${ICONS[p]}
                <span class="sb-dot"></span>
              </div>
              <div class="sb-info">
                <div class="sb-name">${name}</div>
                <div class="sb-sub sb-sub-ok">${timeAgo(sess.savedAt)}</div>
              </div>
              ${user.av
                ? `<img class="sb-av" src="${user.av}" onerror="this.style.display='none'" alt="">`
                : `<div class="sb-av-init" style="background:${c}18;color:${c}">${(user.name||'?')[0].toUpperCase()}</div>`
              }
              <button class="sb-exit" data-action="logout" data-p="${p}"
                      title="Выйти из ${PROVIDER_LABELS[p]}">
                <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                  <line x1="18" y1="6" x2="6" y2="18"/>
                  <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
            </div>`;
        } else {
          return `
            <div class="sb-item sb-empty" data-action="login" data-p="${p}"
                 title="Добавить аккаунт ${PROVIDER_LABELS[p]}">
              <div class="sb-icon sb-icon-off" style="--c:${c}">${ICONS[p]}</div>
              <div class="sb-info">
                <div class="sb-name sb-name-off">${PROVIDER_LABELS[p]}</div>
                <div class="sb-sub">не подключён</div>
              </div>
              <span class="sb-add">+</span>
            </div>`;
        }
      }).join('')}
    </div>
    <div class="sb-footer">
      <div class="sb-footer-text">${count} из 3 подключено</div>
      <div class="sb-bar">
        ${ORDER.map(p => {
          const alive = all[p] && !isExpired(all[p].token);
          return `<div class="sb-seg${alive ? ' on' : ''}" style="--c:${PROVIDER_COLORS[p]}"></div>`;
        }).join('')}
      </div>
    </div>`;

  // ← ИСПРАВЛЕНО: единый делегированный обработчик вместо множества addEventListener
  panel.onclick = e => {
    const el = e.target.closest('[data-action]');
    if (!el) return;
    e.stopPropagation();
    const { action, p } = el.dataset;
    if (action === 'view')   showProfile(p);
    if (action === 'login')  login(p);
    if (action === 'logout') logoutProvider(p);
  };
}

// ════════════════════════════════════════════
// KEYBOARD
// ════════════════════════════════════════════
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT') return;
  const map = { '1':'vk', '2':'yandex', '3':'mailru' };
  if (map[e.key]) {
    const p = map[e.key];
    const s = getSession(p);
    if (s && !isExpired(s.token)) showProfile(p);
    else login(p);
  }
  if (e.key === 'Escape' && activeView) logoutProvider(activeView);
});

// ════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {

  // Кнопки логина (для экрана login-section)
  document.getElementById('btn-vk')?.addEventListener('click',   () => login('vk'));
  document.getElementById('btn-ya')?.addEventListener('click',   () => login('yandex'));
  document.getElementById('btn-mail')?.addEventListener('click', () => login('mailru'));

  // Кнопка выхода — выходит только из activeView
  document.getElementById('btn-logout')?.addEventListener('click', () => {
    if (activeView) logoutProvider(activeView);
  });

  renderSidebar();

  // ════════════════════════════════════════
  // ВНЕШНИЕ САЙТЫ: ?return=URL
  // Сторонний сайт прислал пользователя сюда и просит
  // вернуть его обратно с токеном после входа.
  // Сохраняем в sessionStorage — переживёт переход на VK/Яндекс/Mail.ru и обратно.
  // ════════════════════════════════════════
  const incomingReturn = new URLSearchParams(window.location.search).get('return');
  if (incomingReturn && /^https?:\/\//.test(incomingReturn)) {
    // ← ИСПРАВЛЕНО: проверяем, не использовали ли уже этот return (защита от цикла)
    if (!sessionStorage.getItem('sso_return_used')) {
      sessionStorage.setItem('sso_return', incomingReturn);
    }
  }

  // Читаем токен/ошибку из URL после OAuth redirect
  const qp = new URLSearchParams(window.location.search);
  const hp = new URLSearchParams(window.location.hash.slice(1));
  history.replaceState(null, '', window.location.pathname);

  const token = qp.get('vk_token') || qp.get('ya_token') || qp.get('mr_token')
              || qp.get('token')    || hp.get('token');
  const error = hp.get('error') || qp.get('error') || qp.get('auth_error');

  if (error) {
    const msg = ERROR_LABELS[error] || `Ошибка: ${error}`;
    const detail = qp.get('detail');
    showToast(detail ? `${msg}: ${detail}` : msg, 'err');
    // Если есть живые сессии — показываем первую
    const alive = ORDER.find(p => { const s=getSession(p); return s&&!isExpired(s.token); });
    if (alive) showProfile(alive); else show('login-section');
    return;
  }

  if (token) {
    const decoded  = decodeJwt(token);
    const provider = decoded?.provider;

    if (provider) {
      saveSession(provider, token);
      renderSidebar();
      showProfile(provider);
    } else {
      show('login-section');
      showToast('Не удалось определить провайдер', 'err');
    }

    // Возврат на внешний сайт, если пришли оттуда — передаём токен в URL
    const returnUrl = sessionStorage.getItem('sso_return');
    if (returnUrl) {
      // ← ИСПРАВЛЕНО: помечаем return как использованный, чтобы избежать цикла редиректов
      sessionStorage.setItem('sso_return_used', '1');
      sessionStorage.removeItem('sso_return');
      const sep = returnUrl.includes('?') ? '&' : '?';
      setTimeout(() => { window.location.href = `${returnUrl}${sep}token=${token}`; }, 300);
    }
    return;
  }

  // Нет токена в URL — загружаем первую живую сессию
  show('loading-screen');
  const alive = ORDER.find(p => { const s=getSession(p); return s&&!isExpired(s.token); });
  if (alive) {
    showProfile(alive);
  } else {
    show('login-section');
  }
});