'use strict';

const PROVIDER_LABELS = { vk:'VK ID', yandex:'Яндекс', mailru:'Mail.ru' };
const ERROR_LABELS = {
  vk_auth_failed:     'Ошибка авторизации через VK',
  yandex_auth_failed: 'Ошибка авторизации через Яндекс',
  mailru_auth_failed: 'Ошибка авторизации через Mail.ru',
  invalid_code:       'Недействительный код',
  invalid_state:      'Ошибка безопасности — попробуйте снова',
};

// ── IN-MEMORY TOKEN ──────────────────────────────────────────────────────────
let _token=null, _issuedAt=null;
let activeProvider = null; // Текущий активный провайдер (с токеном)
const TOKEN_TTL=15*60;
const getToken  = ()  => _token;
const setToken  = t   => { _token=t; _issuedAt=Date.now(); };
const clearToken= ()  => { _token=null; _issuedAt=null; };

// ── SESSION HISTORY (localStorage) ───────────────────────────────────────────
const SK='sso_sessions', UK='sso_last_update';
const getSessions  = () => { try{ return JSON.parse(localStorage.getItem(SK)||'{}'); }catch{ return {}; } };
const saveSession  = (p,d) => { const s=getSessions(); s[p]={...d,ts:Date.now()}; localStorage.setItem(SK,JSON.stringify(s)); };
const setLastUpdate= a => { localStorage.setItem(UK,JSON.stringify({time:Date.now(),action:a})); renderUpdateWidget(); };
const getLastUpdate= () => { try{ return JSON.parse(localStorage.getItem(UK)); }catch{ return null; } };

// ── FETCH ────────────────────────────────────────────────────────────────────
async function apiFetch(url, opts={}, ms=15000) {
  const ctrl=new AbortController();
  const tid=setTimeout(()=>ctrl.abort(), ms);
  try {
    return await fetch(url, {
      ...opts, credentials:'include', signal:ctrl.signal,
      headers:{ ...(opts.headers||{}), 'X-Requested-With':'XMLHttpRequest', ...(getToken()?{Authorization:`Bearer ${getToken()}`}:{}) },
    });
  } finally { clearTimeout(tid); }
}

// ── UI ────────────────────────────────────────────────────────────────────────
function show(id) {
  // Скрываем все и показываем только нужный блок с правильным display
  ['loading-screen','login-section','user-section'].forEach(s => {
    const el = document.getElementById(s);
    if (!el) return;
    if (s === id) {
      if (s === 'loading-screen') {
        el.style.display = 'flex';   // loading-screen использует flex
      } else {
        el.style.display = 'block';  // user-section и login-section используют block
      }
    } else {
      el.style.display = 'none';    // Скрываем остальные
    }
  });
}

function setLoadingMsg(msg) { const e=document.getElementById('loading-text'); if(e) e.textContent=msg; }
function showToast(msg, ok=false) {
  const t=document.getElementById('toast');
  if (!t) return;
  t.textContent=msg; t.className=`toast show${ok?' toast-ok':''}`;
  setTimeout(()=>t.classList.remove('show'), 5000);
}
const PM={vk:'vk',yandex:'ya',mailru:'mail'};
function setButtonLoading(p, on) {
  const btn=document.getElementById(`btn-${PM[p]}`), arrow=document.getElementById(`arrow-${PM[p]}`);
  if (!btn) return;
  btn.disabled=on;
  arrow.innerHTML=on?'<span class="spinner-inline"></span>':'→';
  if (on) document.body.className=p==='yandex'?'glow-ya':p==='mailru'?'glow-mail':'';
}

// ── SPARKLE ───────────────────────────────────────────────────────────────────
function sparkle(x,y) {
  for (let i=0;i<14;i++){
    const el=document.createElement('div'); el.className='sparkle-dot';
    const a=(i/14)*Math.PI*2, d=45+Math.random()*50;
    el.style.cssText=`left:${x}px;top:${y}px;--tx:${Math.cos(a)*d}px;--ty:${Math.sin(a)*d}px;background:hsl(${Math.random()*80+160},100%,65%)`;
    document.body.appendChild(el); setTimeout(()=>el.remove(),900);
  }
}

// ── LOGIN ─────────────────────────────────────────────────────────────────────
async function login(provider) {
  setButtonLoading(provider, true);
  try {
    const res=await apiFetch(`/auth/${provider}`,{},25000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const {authUrl}=await res.json();
    window.location.href=authUrl;
  } catch(e) {
    setButtonLoading(provider, false);
    document.body.className='';
    showToast(e.name==='AbortError'
      ? 'Сервер просыпается... подождите ~30 сек и попробуйте снова'
      : 'Ошибка соединения с сервером');
  }
}

// ── FETCH ME ──────────────────────────────────────────────────────────────────
async function fetchMe() {
  if (!getToken()) return null;
  try { const r=await apiFetch('/auth/me',{},20000); return r.ok?r.json():null; }
  catch { return null; }
}

// ── REFRESH ───────────────────────────────────────────────────────────────────
async function tryRefresh() {
  try {
    const r=await apiFetch('/auth/refresh',{method:'POST'},20000);
    if (!r.ok) return false;
    const {accessToken}=await r.json(); setToken(accessToken); return true;
  } catch { return false; }
}

// ── LOGOUT ────────────────────────────────────────────────────────────────────
async function logout() {
  try { await apiFetch('/auth/logout', {method:'POST'}, 8000); } catch{}

  // Очищаем ВСЕ сессии из localStorage после выхода
  // (они привязаны к одному refresh-cookie, который сервер уже инвалидировал)
  localStorage.removeItem(SK);

  clearToken(); stopCountdown(); document.body.className='';
  activeProvider = null;
  setLastUpdate('Выход из аккаунта');
  show('login-section');
  renderSidebar();
}

// ── RENDER USER ───────────────────────────────────────────────────────────────
function renderUser(user) {
  activeProvider = user.provider;
  const name    =user.name||user.userId;
  const initials=name.split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2)||'?';
  document.getElementById('user-name').textContent         =name;
  document.getElementById('user-email').textContent        =user.email||'Email не указан';
  document.getElementById('user-id').textContent           =user.userId;
  document.getElementById('user-email-detail').textContent =user.email||'—';
  document.getElementById('user-provider').textContent     =PROVIDER_LABELS[user.provider]||user.provider;
  document.getElementById('avatar-fallback').textContent   =initials;
  const img=document.getElementById('avatar-img');
  if (user.avatar) {
    img.onload =()=>{ document.getElementById('avatar-fallback').style.display='none'; img.style.display=''; };
    img.onerror=()=>{ img.style.display='none'; };
    img.src=user.avatar;
  }
  const badge=document.getElementById('provider-badge');
  badge.textContent=PROVIDER_LABELS[user.provider]||user.provider;
  badge.className=`badge badge-${user.provider}`;
  document.body.className=user.provider==='yandex'?'glow-ya':user.provider==='mailru'?'glow-mail':'';
  saveSession(user.provider,{name,email:user.email,avatar:user.avatar,userId:user.userId}); // <-- Сохраняем userId
  setLastUpdate(`Вход через ${PROVIDER_LABELS[user.provider]}`);
  renderSidebar(); startCountdown();
  show('user-section');
  setTimeout(()=>{
    const c=document.querySelector('.card');
    if (c){const r=c.getBoundingClientRect(); sparkle(r.left+r.width/2, r.top+r.height/2);}
  },200);
}

// ── SWITCH TO PROVIDER ──────────────────────────────────────────────────────
function switchToProvider(provider) {
  if (activeProvider === provider) {
    // Это активный аккаунт — обновляем данные с бэкенда
    fetchMe().then(u => {
      if (u) renderUser(u);
      else {
        clearToken();
        show('login-section');
        renderSidebar();
        showToast('Сессия истекла, войдите снова');
      }
    });
    return;
  }

  // Не-активный провайдер — SSO поддерживает одну сессию одновременно.
  // Предлагаем войти через него (новая авторизация).
  // Текущий токен остаётся активным до явного выхода.
  showToast(`Войдите через ${PROVIDER_LABELS[provider] || provider} для переключения аккаунта`);
  login(provider);
}

// ── RENDER USER FROM SESSION ──────────────────────────────────────────────
function renderUserFromSession(sess, provider) {
  const name = sess.name || 'Пользователь';
  document.getElementById('user-name').textContent = name;
  document.getElementById('user-email').textContent = sess.email || 'Email не указан';
  document.getElementById('user-email-detail').textContent = sess.email || '—';
  document.getElementById('user-id').textContent = sess.userId || `${provider}_${sess.ts}`;
  document.getElementById('user-provider').textContent = PROVIDER_LABELS[provider] || provider;
  
  const badge = document.getElementById('provider-badge');
  badge.textContent = PROVIDER_LABELS[provider] || provider;
  badge.className = `badge badge-${provider}`;
  
  // Аватар
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
  
  // Эффект свечения под цвет провайдера
  document.body.className = provider === 'yandex' ? 'glow-ya' : provider === 'mailru' ? 'glow-mail' : '';
  
  // Скрываем таймер, если это не активный аккаунт
  const sessionTimer = document.querySelector('.session-row');
  if (provider !== activeProvider) {
    if (sessionTimer) sessionTimer.style.display = 'none';
  } else {
    if (sessionTimer) sessionTimer.style.display = 'flex';
    if (!_cd) startCountdown();
  }
  
  show('user-section');
}

// ── COUNTDOWN ─────────────────────────────────────────────────────────────────
let _cd=null;
function startCountdown() {
  stopCountdown();
  const el=document.getElementById('session-countdown'); if (!el) return;
  const tick=()=>{
    const elapsed=_issuedAt?Math.floor((Date.now()-_issuedAt)/1000):TOKEN_TTL;
    const left=Math.max(0,TOKEN_TTL-elapsed);
    el.textContent=`${Math.floor(left/60).toString().padStart(2,'0')}:${(left%60).toString().padStart(2,'0')}`;
    el.style.color=left<120?'var(--err)':left<300?'#f5a623':'var(--ok)';
    if (left===0) tryRefresh().then(ok=>{ if(ok) _issuedAt=Date.now(); });
  };
  tick(); _cd=setInterval(tick,1000);
}
function stopCountdown(){ if(_cd){clearInterval(_cd);_cd=null;} }

// ── SIDEBAR ───────────────────────────────────────────────────────────────────
const ICONS={
  vk:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.579 6.855c.14-.465 0-.806-.662-.806h-2.193c-.558 0-.813.295-.953.619 0 0-1.115 2.719-2.695 4.482-.513.513-.745.675-1.024.675-.14 0-.343-.162-.343-.627V6.855c0-.558-.162-.806-.626-.806H9.642c-.348 0-.557.258-.557.504 0 .528.79.65.871 2.138v3.228c0 .707-.128.836-.406.836-.745 0-2.557-2.731-3.63-5.858C5.715 6.419 5.504 6.05 4.944 6.05H2.75C2.122 6.05 2 6.345 2 6.669c0 .582.745 3.473 3.473 7.299C7.297 16.588 9.909 18 12.279 18c1.442 0 1.62-.325 1.62-.882v-1.97c0-.628.132-.753.576-.753.326 0 .885.163 2.193 1.425 1.494 1.494 1.74 2.18 2.58 2.18h2.193c.627 0 .941-.325.76-.966-.198-.639-.91-1.568-1.86-2.669-.513-.605-1.282-1.257-1.515-1.583-.326-.42-.233-.605 0-.977 0 0 2.681-3.777 2.961-5.059z"/></svg>`,
  yandex:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M13.32 21h-2.495V13.51H9.21L5.88 21H3.15l3.555-7.88c-1.98-.84-3.03-2.505-3.03-4.74C3.675 5.085 5.88 3 9.45 3H13.32v18zm-2.495-9.495V5.01H9.36c-1.98 0-3.15 1.17-3.15 3.18 0 1.98 1.125 3.315 3.285 3.315h1.33z"/></svg>`,
  mailru:`<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 13.5L2 7V18h20V7l-10 6.5zM12 11L2 5h20l-10 6z"/></svg>`,
};
const COLORS={vk:'#0077FF',yandex:'#FC3F1D',mailru:'#168DE2'};
const ORDER=['vk','yandex','mailru'];
const timeAgo=ts=>{ const d=Math.floor((Date.now()-ts)/1000); if(d<60) return 'только что'; if(d<3600) return `${Math.floor(d/60)} мин назад`; if(d<86400) return `${Math.floor(d/3600)} ч назад`; return `${Math.floor(d/86400)} д назад`; };

function renderSidebar() {
  const panel=document.getElementById('sidebar-panel'); if(!panel) return;
  const s=getSessions(); const count=ORDER.filter(p=>s[p]).length;
  panel.innerHTML=`
    <div class="sb-header"><span class="sb-title">Аккаунты</span><span class="sb-hint">1 · 2 · 3</span></div>
    <div class="sb-list">${ORDER.map((p,i)=>{
      const sess=s[p],c=COLORS[p];
      const isActive=activeProvider===p;
      return `<div class="sb-item${sess?' connected':''}${isActive?' active':''}" data-p="${p}"${sess?' data-connected="true"':''}>
        <div class="sb-icon" style="--c:${c}">${ICONS[p]}${sess?'<span class="sb-dot"></span>':''}</div>
        <div class="sb-info"><div class="sb-name">${PROVIDER_LABELS[p]}</div>
          <div class="sb-sub" style="color:${sess?'var(--ok)':'var(--muted2)'}">${sess?timeAgo(sess.ts):`клавиша ${i+1}`}</div>
        </div>
        ${sess&&sess.avatar?`<img class="sb-av" src="${sess.avatar}" onerror="this.style.display='none'" alt="">`
          :sess?`<div class="sb-av sb-av-init" style="background:${c}22;color:${c}">${(sess.name||'?')[0].toUpperCase()}</div>`
          :`<div class="sb-arrow" style="color:${c}">→</div>`}
      </div>`;
    }).join('')}</div>
    <div class="sb-footer">
      <div class="sb-footer-text">${count} из 3 подключено</div>
      <div class="sb-bar">${ORDER.map(p=>`<div class="sb-seg${s[p]?' on':''}" style="--c:${COLORS[p]}"></div>`).join('')}</div>
    </div>`;
  panel.querySelectorAll('.sb-item').forEach(el=>{
    el.addEventListener('click',()=>{
      const p=el.dataset.p;
      // Если аккаунт подключен → переключаем UI
      if (el.dataset.connected==='true') {
        switchToProvider(p);
      } else {
        // Не подключен → запускаем авторизацию
        const id={vk:'btn-vk',yandex:'btn-ya',mailru:'btn-mail'}[p];
        const btn=document.getElementById(id);
        if(btn&&!btn.disabled){ btn.classList.add('highlight-pulse'); setTimeout(()=>{btn.classList.remove('highlight-pulse');login(p);},150); }
      }
    });
  });
}

// ── UPDATE WIDGET ─────────────────────────────────────────────────────────────
function renderUpdateWidget() {
  const el=document.getElementById('update-widget'); if(!el) return;
  const now=new Date();
  const hh=now.getHours().toString().padStart(2,'0');
  const mm=now.getMinutes().toString().padStart(2,'0');
  const ss=now.getSeconds().toString().padStart(2,'0');
  const upd=getLastUpdate();
  el.innerHTML=`<div class="upd-clock">${hh}:${mm}<span class="upd-sec">:${ss}</span></div>${upd?`<div class="upd-sep">·</div><div class="upd-info"><div class="upd-action">${upd.action}</div><div class="upd-ago">${timeAgo(upd.time)}</div></div>`:''}`;
}

// ── KEYBOARD ──────────────────────────────────────────────────────────────────
document.addEventListener('keydown', e=>{
  if (e.target.tagName==='INPUT') return;
  const map={'1':'vk','2':'yandex','3':'mailru'};
  if (map[e.key]&&document.getElementById('login-section').style.display!=='none') login(map[e.key]);
  if (e.key==='Escape'&&document.getElementById('user-section').style.display!=='none') logout();
});

// ── CHECK AUTH ────────────────────────────────────────────────────────────────
async function checkAuth() {
  const wt=setTimeout(()=>setLoadingMsg('Сервер просыпается... ~30 сек'), 4000);
  try {
    if (getToken()) {
      const u=await fetchMe();
      if (u){ clearTimeout(wt); renderUser(u); return; }
      clearToken();
    }
    const ok=await tryRefresh();
    if (ok){
      const u=await fetchMe();
      if (u){ clearTimeout(wt); renderUser(u); return; }
    }
  } catch{}
  clearTimeout(wt);
  show('login-section');
}

// ── INIT ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btn-vk')?.addEventListener('click',   ()=>login('vk'));
  document.getElementById('btn-ya')?.addEventListener('click',   ()=>login('yandex'));
  document.getElementById('btn-mail')?.addEventListener('click', ()=>login('mailru'));
  document.getElementById('btn-logout')?.addEventListener('click', logout);

  renderSidebar();
  setInterval(renderUpdateWidget, 1000);
  renderUpdateWidget();

  // Читаем токен из ВСЕХ возможных мест:
  // ?vk_token=  ?ya_token=  ?mr_token=  ?token=  #token=  #error=
  const qp=new URLSearchParams(window.location.search);
  const hp=new URLSearchParams(window.location.hash.slice(1));

  // Убираем параметры из URL сразу
  history.replaceState(null,'', window.location.pathname);

  const token = qp.get('vk_token') || qp.get('ya_token') || qp.get('mr_token') || qp.get('token') || hp.get('token');
  const error = hp.get('error') || qp.get('error') || qp.get('auth_error');

  if (error) {
    const detail = qp.get("detail"); const msg = ERROR_LABELS[error] || `Ошибка: ${error}`; showToast(detail ? `${msg}: ${detail}` : msg);
    show('login-section'); renderSidebar(); return;
  }

  if (token) {
    setToken(token);
    setLoadingMsg('Загружаем профиль...');

    // Пробуем получить профиль, с retry если сервер ещё не готов
    async function loadProfileWithRetry(attempts = 3) {
      for (let i = 0; i < attempts; i++) {
        if (i > 0) {
          setLoadingMsg(`Повторная попытка ${i}/${attempts-1}...`);
          await new Promise(r => setTimeout(r, 2000));
        }
        const u = await fetchMe();
        if (u) { renderUser(u); renderSidebar(); return; }
      }
      // Все попытки провалились — показываем логин с ошибкой
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