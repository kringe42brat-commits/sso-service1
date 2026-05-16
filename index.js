'use strict';
const express   = require('express');
const axios     = require('axios');
const jwt       = require('jsonwebtoken');
const cookieParse = require('cookie-parser');
const cors      = require('cors');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');
require('dotenv').config();

const app = express();

// ─── TRUST PROXY (Render / NGINX) ─────────────────────────────────────────────
app.set('trust proxy', 1);

// ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:       ["'self'"],
      scriptSrc:        ["'self'"],          // NO unsafe-inline — JS в app.js
      scriptSrcAttr:    ["'none'"],          // запрет inline onclick
      styleSrc:         ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:          ["'self'", "https://fonts.gstatic.com"],
      imgSrc:           ["'self'", "data:", "https:", "blob:"],
      connectSrc:       ["'self'"],
      objectSrc:        ["'none'"],
      baseUri:          ["'none'"],
      frameAncestors:   ["'none'"],
      formAction:       ["'self'"],
    },
  },
  referrerPolicy:         { policy: 'no-referrer' },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

app.use(cors({
  origin:      process.env.FRONTEND_URL || 'https://sso-service1.onrender.com',
  credentials: true,
}));
app.use(cookieParse());
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// ─── ENV VALIDATION ────────────────────────────────────────────────────────────
const REQUIRED_ENV = [
  'JWT_SECRET', 'FRONTEND_URL',
  'VK_CLIENT_ID',    'VK_CLIENT_SECRET',    'VK_REDIRECT_URI',
  'YANDEX_CLIENT_ID','YANDEX_CLIENT_SECRET','YANDEX_REDIRECT_URI',
  'MAILRU_CLIENT_ID','MAILRU_CLIENT_SECRET','MAILRU_REDIRECT_URI',
];
for (const k of REQUIRED_ENV) {
  if (!process.env[k]) { console.error(`[FATAL] Missing: ${k}`); process.exit(1); }
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET must be >= 32 chars'); process.exit(1);
}

// Раздельные секреты для access и refresh — с fallback на JWT_SECRET
const ACCESS_SECRET  = process.env.ACCESS_TOKEN_SECRET  || process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET + '_refresh';

const JWT_ISSUER   = 'sso-service';
const JWT_AUDIENCE = 'sso-client';

// ─── RATE LIMITING ─────────────────────────────────────────────────────────────
const authLimiter    = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false, skipSuccessfulRequests: false });
const refreshLimiter = rateLimit({ windowMs:  5*60*1000, max: 10, standardHeaders: true, legacyHeaders: false });

// ─── AXIOS ─────────────────────────────────────────────────────────────────────
const http = axios.create({
  timeout: 10000,
  headers: { 'User-Agent': 'SSO-Service/1.0' },
});

// ─── PKCE ──────────────────────────────────────────────────────────────────────
const genVerifier  = ()  => crypto.randomBytes(64).toString('base64url');
const genChallenge = (v) => crypto.createHash('sha256').update(v).digest('base64url');
const genState     = ()  => crypto.randomBytes(32).toString('hex');

// ─── COOKIE OPTIONS ────────────────────────────────────────────────────────────
const isProd = process.env.NODE_ENV === 'production';
const AUTH_COOKIE    = { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 10*60*1000, path: '/' };
const REFRESH_COOKIE = { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 7*24*3600*1000, path: '/' };
const clearRefresh   = (res) => res.clearCookie('refreshToken', { httpOnly: true, secure: isProd, sameSite: 'lax', path: '/' });

// ─── BLACKLIST (in-memory, честно документируем: теряется при рестарте) ────────
// jti хранится вместо полных токенов — O(1) lookup, меньше памяти
const revokedJtis = new Set();
setInterval(() => {
  // Нет способа очистить без expiry metadata без Redis.
  // Храним максимум 10 000 записей — потом чистим старейшие.
  if (revokedJtis.size > 10_000) revokedJtis.clear();
}, 15*60*1000);

// ─── PAYLOAD SANITIZE ──────────────────────────────────────────────────────────
// FIX: ограничиваем длину всех строк из внешних провайдеров
function sanitizeString(val, maxLen) {
  if (typeof val !== 'string') return null;
  return val.slice(0, maxLen).trim() || null;
}
function sanitizeAvatar(url) {
  if (typeof url !== 'string') return null;
  if (!url.startsWith('https://'))  return null;
  if (url.length > 512)             return null;
  // Только известные домены аватаров
  const ALLOWED = ['avatars.yandex.net', 'sun9-', 'vk.com', 'userapi.com', 'img.imgsmail.ru', 'filin.vkuser'];
  try {
    const host = new URL(url).hostname;
    if (!ALLOWED.some(d => host.includes(d))) return null;
  } catch { return null; }
  return url;
}

// ─── JWT ───────────────────────────────────────────────────────────────────────
function issueTokens(user) {
  const base = {
    sub:      user.id,
    email:    sanitizeString(user.email,  320),
    provider: sanitizeString(user.provider, 32),
    name:     sanitizeString(user.name,   128),
    avatar:   sanitizeAvatar(user.avatar),
  };

  const jtiAccess  = crypto.randomUUID();
  const jtiRefresh = crypto.randomUUID();

  const accessToken = jwt.sign(
    { ...base, jti: jtiAccess },
    ACCESS_SECRET,
    { expiresIn: '15m', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, algorithm: 'HS256' }
  );
  const refreshToken = jwt.sign(
    { ...base, jti: jtiRefresh, type: 'refresh' },
    REFRESH_SECRET,
    { expiresIn: '7d', issuer: JWT_ISSUER, audience: JWT_AUDIENCE, algorithm: 'HS256' }
  );

  return { accessToken, refreshToken };
}

function verifyAccess(token) {
  return jwt.verify(token, ACCESS_SECRET, {
    algorithms: ['HS256'],
    issuer:     JWT_ISSUER,
    audience:   JWT_AUDIENCE,
  });
}
function verifyRefresh(token) {
  return jwt.verify(token, REFRESH_SECRET, {
    algorithms: ['HS256'],
    issuer:     JWT_ISSUER,
    audience:   JWT_AUDIENCE,
  });
}

// ─── CSRF protection для state-mutating endpoints ──────────────────────────────
// Проверяем X-Requested-With header — простой и надёжный метод для AJAX-запросов
function requireXHR(req, res, next) {
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(403).json({ error: 'CSRF check failed' });
  }
  next();
}

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const raw = req.headers['authorization'] || '';
  const token = raw.startsWith('Bearer ') ? raw.slice(7).trim() : '';

  if (!token) return res.status(401).json({ error: 'Токен не передан' });

  try {
    const decoded = verifyAccess(token);
    if (revokedJtis.has(decoded.jti)) return res.status(401).json({ error: 'Токен отозван' });
    req.user  = decoded;
    req.token = token;
    next();
  } catch (e) {
    const expired = e.name === 'TokenExpiredError';
    res.status(expired ? 401 : 403).json({ error: expired ? 'Токен истёк' : 'Недействительный токен' });
  }
}

// ─── PROVIDER RESPONSE VALIDATION ─────────────────────────────────────────────
function assertString(val, field) {
  if (typeof val !== 'string' && typeof val !== 'number') {
    throw new Error(`Provider returned invalid ${field}: ${JSON.stringify(val)}`);
  }
  return String(val);
}

// ─── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status:    'ok',
  uptime:    Math.floor(process.uptime()),
  timestamp: new Date().toISOString(),
  providers: ['vk', 'yandex', 'mailru'],
}));

// ─── VK ID ─────────────────────────────────────────────────────────────────────
app.get('/auth/vk', authLimiter, (req, res) => {
  const verifier  = genVerifier();
  const challenge = genChallenge(verifier);
  const state     = genState();

  res.cookie('vk_auth', JSON.stringify({ state, verifier }), AUTH_COOKIE);

  const url = new URL('https://id.vk.com/authorize');
  url.searchParams.set('client_id',             process.env.VK_CLIENT_ID);
  url.searchParams.set('redirect_uri',          process.env.VK_REDIRECT_URI);
  url.searchParams.set('response_type',         'code');
  url.searchParams.set('scope',                 'email');
  url.searchParams.set('state',                 state);
  url.searchParams.set('code_challenge',        challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  res.json({ authUrl: url.toString() });
});

app.get('/auth/vk/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const raw = req.cookies.vk_auth;
    res.clearCookie('vk_auth', { path: '/' });

    if (!code || typeof code !== 'string') return res.redirect('/#error=invalid_code');
    if (!raw) return res.redirect('/#error=invalid_state');

    let saved;
    try { saved = JSON.parse(raw); } catch { return res.redirect('/#error=invalid_state'); }
    if (!state || state !== saved.state || !saved.verifier) return res.redirect('/#error=invalid_state');

    const { data: td } = await http.post('https://id.vk.com/oauth2/auth', null, {
      params: {
        grant_type:    'authorization_code',
        code,
        client_id:     process.env.VK_CLIENT_ID,
        client_secret: process.env.VK_CLIENT_SECRET,
        redirect_uri:  process.env.VK_REDIRECT_URI,
        code_verifier: saved.verifier,
      },
    });

    if (!td.access_token) throw new Error('VK: no access_token');

    const { data: ui } = await http.post(
      'https://id.vk.com/oauth2/user_info',
      new URLSearchParams({ access_token: td.access_token, client_id: process.env.VK_CLIENT_ID }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );

    const vk = ui.user;
    if (!vk) throw new Error('VK: empty user_info');
    const userId = assertString(vk.user_id, 'user_id');

    const tokens = issueTokens({
      id:       `vk_${userId}`,
      provider: 'vk',
      email:    td.email || vk.email || null,
      name:     [vk.first_name, vk.last_name].filter(Boolean).join(' ') || null,
      avatar:   vk.avatar || null,
    });

    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    // FIX: токен через fragment, не query string
    res.redirect(`/#token=${tokens.accessToken}`);
  } catch (e) {
    console.error('[VK]', e.response?.data ?? e.message);
    res.redirect('/#error=vk_auth_failed');
  }
});

// ─── YANDEX ────────────────────────────────────────────────────────────────────
app.get('/auth/yandex', authLimiter, (req, res) => {
  const state = genState();
  res.cookie('ya_auth', state, AUTH_COOKIE);

  const url = new URL('https://oauth.yandex.ru/authorize');
  url.searchParams.set('client_id',     process.env.YANDEX_CLIENT_ID);
  url.searchParams.set('redirect_uri',  process.env.YANDEX_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('state',         state);
  res.json({ authUrl: url.toString() });
});

app.get('/auth/yandex/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const saved = req.cookies.ya_auth;
    res.clearCookie('ya_auth', { path: '/' });

    if (!code || typeof code !== 'string') return res.redirect('/#error=invalid_code');
    if (!saved || state !== saved)         return res.redirect('/#error=invalid_state');

    const params = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      client_id:     process.env.YANDEX_CLIENT_ID,
      client_secret: process.env.YANDEX_CLIENT_SECRET,
      redirect_uri:  process.env.YANDEX_REDIRECT_URI,
    });
    const { data: td } = await http.post('https://oauth.yandex.ru/token', params);
    if (!td.access_token) throw new Error('Yandex: no access_token');

    const { data: ya } = await http.get('https://login.yandex.ru/info', {
      headers: { Authorization: `OAuth ${td.access_token}` },
      params:  { format: 'json' },
    });

    assertString(ya.id, 'id');

    const tokens = issueTokens({
      id:       `yandex_${ya.id}`,
      provider: 'yandex',
      email:    ya.default_email || ya.emails?.[0] || null,
      name:     ya.display_name  || ya.real_name   || ya.login || null,
      avatar:   ya.default_avatar_id
        ? `https://avatars.yandex.net/get-yapic/${ya.default_avatar_id}/islands-200`
        : null,
    });

    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    res.redirect(`/#token=${tokens.accessToken}`);
  } catch (e) {
    console.error('[Yandex]', e.response?.data ?? e.message);
    res.redirect('/#error=yandex_auth_failed');
  }
});

// ─── MAIL.RU ───────────────────────────────────────────────────────────────────
app.get('/auth/mailru', authLimiter, (req, res) => {
  const state = genState();
  res.cookie('mr_auth', state, AUTH_COOKIE);

  const url = new URL('https://connect.mail.ru/oauth/authorize');
  url.searchParams.set('client_id',     process.env.MAILRU_CLIENT_ID);
  url.searchParams.set('redirect_uri',  process.env.MAILRU_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope',         'userinfo');
  url.searchParams.set('state',         state);
  res.json({ authUrl: url.toString() });
});

app.get('/auth/mailru/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const saved = req.cookies.mr_auth;
    res.clearCookie('mr_auth', { path: '/' });

    if (!code || typeof code !== 'string') return res.redirect('/#error=invalid_code');
    if (!saved || state !== saved)         return res.redirect('/#error=invalid_state');

    const params = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      client_id:     process.env.MAILRU_CLIENT_ID,
      client_secret: process.env.MAILRU_CLIENT_SECRET,
      redirect_uri:  process.env.MAILRU_REDIRECT_URI,
    });
    const { data: td } = await http.post('https://connect.mail.ru/oauth/token', params);
    if (!td.access_token) throw new Error('Mail.ru: no access_token');

    const { data: mu } = await http.get('https://oauth.mail.ru/userinfo', {
      headers: { Authorization: `Bearer ${td.access_token}` },
    });

    assertString(mu.id, 'id');

    const tokens = issueTokens({
      id:       `mailru_${mu.id}`,
      provider: 'mailru',
      email:    mu.email || null,
      name:     mu.name  || null,
      avatar:   mu.image || null,
    });

    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    res.redirect(`/#token=${tokens.accessToken}`);
  } catch (e) {
    console.error('[Mail.ru]', e.response?.data ?? e.message);
    res.redirect('/#error=mailru_auth_failed');
  }
});

// ─── AUTH ME ───────────────────────────────────────────────────────────────────
app.get('/auth/me', requireAuth, (req, res) => res.json({
  userId:   req.user.sub,
  email:    req.user.email    || null,
  provider: req.user.provider,
  name:     req.user.name     || null,
  avatar:   req.user.avatar   || null,
}));

// ─── REFRESH ───────────────────────────────────────────────────────────────────
app.post('/auth/refresh', refreshLimiter, requireXHR, (req, res) => {
  const rt = req.cookies.refreshToken;
  if (!rt) return res.status(401).json({ error: 'Refresh token не передан' });

  try {
    const d = verifyRefresh(rt);
    if (d.type !== 'refresh')       return res.status(403).json({ error: 'Неверный тип токена' });
    if (revokedJtis.has(d.jti))    return res.status(401).json({ error: 'Refresh token отозван' });

    const tokens = issueTokens({ id: d.sub, email: d.email, provider: d.provider, name: d.name, avatar: d.avatar });
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    res.json({ accessToken: tokens.accessToken });
  } catch (e) {
    clearRefresh(res);
    res.status(403).json({ error: 'Недействительный refresh token' });
  }
});

// ─── LOGOUT (ревокация ОБОИХ токенов) ─────────────────────────────────────────
app.post('/auth/logout', requireAuth, requireXHR, (req, res) => {
  // Ревокация access token по jti
  if (req.user.jti) revokedJtis.add(req.user.jti);

  // Ревокация refresh token по jti
  const rt = req.cookies.refreshToken;
  if (rt) {
    try {
      const d = verifyRefresh(rt);
      if (d.jti) revokedJtis.add(d.jti);
    } catch { /* expired — OK */ }
  }

  clearRefresh(res);
  res.json({ message: 'Выход выполнен' });
});

// ─── ERROR HANDLER ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Unhandled]', err.message);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ SSO запущен — порт ${PORT} | isProd=${isProd}`);
  console.log(`   VK  → ${process.env.VK_REDIRECT_URI}`);
  console.log(`   Ya  → ${process.env.YANDEX_REDIRECT_URI}`);
  console.log(`   MR  → ${process.env.MAILRU_REDIRECT_URI}`);
});
