const express  = require('express');
const axios    = require('axios');
const jwt      = require('jsonwebtoken');
const cookieParse = require('cookie-parser');
const cors     = require('cors');
const crypto   = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet   = require('helmet');
require('dotenv').config();

const app = express();

// ─────────────────────────────────────────────
// SECURITY MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:       ["'self'", "https://fonts.gstatic.com"],
      imgSrc:        ["'self'", "data:", "https:", "blob:"],
      connectSrc:    ["'self'"],
    },
  },
}));
app.use(cors({ origin: process.env.FRONTEND_URL || 'https://sso-service1.onrender.com', credentials: true }));
app.use(cookieParse());
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// ─────────────────────────────────────────────
// ENV VALIDATION — проверяем при старте
// ─────────────────────────────────────────────
const REQUIRED_ENV = [
  'JWT_SECRET','FRONTEND_URL',
  'VK_CLIENT_ID','VK_CLIENT_SECRET','VK_REDIRECT_URI',
  'YANDEX_CLIENT_ID','YANDEX_CLIENT_SECRET','YANDEX_REDIRECT_URI',
  'MAILRU_CLIENT_ID','MAILRU_CLIENT_SECRET','MAILRU_REDIRECT_URI',
];
for (const k of REQUIRED_ENV) {
  if (!process.env[k]) { console.error(`[FATAL] Missing env var: ${k}`); process.exit(1); }
}
// FIX #5: минимальная длина JWT_SECRET
if (process.env.JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET must be at least 32 characters'); process.exit(1);
}

// ─────────────────────────────────────────────
// RATE LIMITING
// ─────────────────────────────────────────────
const authLimiter    = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false });
const refreshLimiter = rateLimit({ windowMs:  5*60*1000, max: 10, standardHeaders: true, legacyHeaders: false });

// ─────────────────────────────────────────────
// AXIOS — с таймаутом и базовыми заголовками
// ─────────────────────────────────────────────
const http = axios.create({
  timeout: 10000,
  headers: { 'User-Agent': 'SSO-Service/1.0' },
});

// ─────────────────────────────────────────────
// PKCE helpers
// ─────────────────────────────────────────────
const genVerifier  = ()  => crypto.randomBytes(64).toString('base64url');
const genChallenge = (v) => crypto.createHash('sha256').update(v).digest('base64url');
const genState     = ()  => crypto.randomBytes(32).toString('hex');

// ─────────────────────────────────────────────
// COOKIE OPTIONS
// FIX #4: уникальные имена с суффиксом state-значения не нужны —
// достаточно хранить state + verifier в одном JSON-cookie per provider
// ─────────────────────────────────────────────
const isProd = process.env.NODE_ENV === 'production';
const mkCookieOpts = (maxAgeSec) => ({
  httpOnly: true,
  secure:   isProd,
  sameSite: 'lax',
  maxAge:   maxAgeSec * 1000,
});
const AUTH_COOKIE  = mkCookieOpts(10 * 60);     // 10 мин для state/verifier
const REFRESH_COOKIE = mkCookieOpts(7 * 24 * 3600); // 7 дней

// ─────────────────────────────────────────────
// JWT helpers
// ─────────────────────────────────────────────

// FIX #3: in-memory blacklist — честно документируем ограничение
// (при рестарте токены до 15мин могут работать — приемлемо для студ. проекта)
const revokedTokens = new Set();
setInterval(() => {
  for (const t of revokedTokens) {
    try { jwt.verify(t, process.env.JWT_SECRET); }
    catch (e) { if (e.name === 'TokenExpiredError') revokedTokens.delete(t); }
  }
}, 15 * 60 * 1000); // чистим каждые 15 мин (= TTL access-токена)

function issueTokens(user) {
  const payload = {
    sub:      user.id,
    email:    user.email    || null,
    provider: user.provider,
    name:     user.name     || null,
    // FIX #7: avatar — только если это https URL, иначе null
    avatar: (typeof user.avatar === 'string' && user.avatar.startsWith('https://'))
              ? user.avatar : null,
  };
  const accessToken  = jwt.sign(payload,                   process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ ...payload, type: 'refresh' }, process.env.JWT_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
}

function requireAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Токен не передан' });
  if (revokedTokens.has(token)) return res.status(401).json({ error: 'Токен отозван' });
  try {
    req.user  = jwt.verify(token, process.env.JWT_SECRET);
    req.token = token;
    next();
  } catch (e) {
    const expired = e.name === 'TokenExpiredError';
    res.status(expired ? 401 : 403).json({ error: expired ? 'Токен истёк' : 'Недействительный токен' });
  }
}

// ─────────────────────────────────────────────
// HEALTH
// ─────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
  status:    'ok',
  uptime:    Math.floor(process.uptime()),
  timestamp: new Date().toISOString(),
  providers: ['vk', 'yandex', 'mailru'],
}));

// ─────────────────────────────────────────────
// VK ID  (PKCE + state в cookie)
// FIX #1: используем id.vk.com/oauth2/user_info вместо несуществующего метода
// ─────────────────────────────────────────────
app.get('/auth/vk', authLimiter, (req, res) => {
  const verifier  = genVerifier();
  const challenge = genChallenge(verifier);
  const state     = genState();

  // Один cookie с JSON — нет коллизии при параллельных сессиях одного браузера
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
    res.clearCookie('vk_auth');

    if (!code  || typeof code  !== 'string') return res.redirect('/?error=invalid_code');
    if (!raw)                                 return res.redirect('/?error=invalid_state');

    let saved;
    try { saved = JSON.parse(raw); } catch { return res.redirect('/?error=invalid_state'); }
    if (!state || state !== saved.state)      return res.redirect('/?error=invalid_state');
    if (!saved.verifier)                      return res.redirect('/?error=invalid_state');

    // Обмен кода на токен
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

    if (!td.access_token) throw new Error('VK: no access_token in response');

    // FIX #1: правильный endpoint для профиля VK ID
    const { data: ui } = await http.post(
      'https://id.vk.com/oauth2/user_info',
      new URLSearchParams({ access_token: td.access_token, client_id: process.env.VK_CLIENT_ID }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    );

    const vkUser = ui.user;
    if (!vkUser || !vkUser.user_id) throw new Error('VK: empty user_info response');

    const tokens = issueTokens({
      id:       `vk_${vkUser.user_id}`,
      provider: 'vk',
      email:    td.email || vkUser.email || null,
      name:     [vkUser.first_name, vkUser.last_name].filter(Boolean).join(' ') || 'VK User',
      avatar:   vkUser.avatar || null,
    });

    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch (e) {
    console.error('[VK callback]', e.response?.data ?? e.message);
    res.redirect('/?error=vk_auth_failed');
  }
});

// ─────────────────────────────────────────────
// ЯНДЕКС ID  (state в cookie)
// ─────────────────────────────────────────────
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
    res.clearCookie('ya_auth');

    if (!code  || typeof code  !== 'string') return res.redirect('/?error=invalid_code');
    if (!saved || state !== saved)            return res.redirect('/?error=invalid_state');

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

    const tokens = issueTokens({
      id:       `yandex_${ya.id}`,
      provider: 'yandex',
      email:    ya.default_email || ya.emails?.[0] || null,
      name:     ya.display_name  || ya.real_name   || ya.login || 'Yandex User',
      avatar:   ya.default_avatar_id
        ? `https://avatars.yandex.net/get-yapic/${ya.default_avatar_id}/islands-200`
        : null,
    });

    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch (e) {
    console.error('[Yandex callback]', e.response?.data ?? e.message);
    res.redirect('/?error=yandex_auth_failed');
  }
});

// ─────────────────────────────────────────────
// MAIL.RU  (state в cookie)
// FIX #2: используем oauth.mail.ru/userinfo — без HMAC-подписи
// ─────────────────────────────────────────────
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
    res.clearCookie('mr_auth');

    if (!code  || typeof code  !== 'string') return res.redirect('/?error=invalid_code');
    if (!saved || state !== saved)            return res.redirect('/?error=invalid_state');

    const params = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      client_id:     process.env.MAILRU_CLIENT_ID,
      client_secret: process.env.MAILRU_CLIENT_SECRET,
      redirect_uri:  process.env.MAILRU_REDIRECT_URI,
    });
    const { data: td } = await http.post('https://connect.mail.ru/oauth/token', params);
    if (!td.access_token) throw new Error('Mail.ru: no access_token');

    // FIX #2: правильный userinfo endpoint — без подписи
    const { data: mu } = await http.get('https://oauth.mail.ru/userinfo', {
      headers: { Authorization: `Bearer ${td.access_token}` },
    });

    if (!mu.id) throw new Error('Mail.ru: empty userinfo response');

    const tokens = issueTokens({
      id:       `mailru_${mu.id}`,
      provider: 'mailru',
      email:    mu.email || null,
      name:     mu.name  || `${mu.first_name || ''} ${mu.last_name || ''}`.trim() || 'Mail User',
      avatar:   mu.image || null,
    });

    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch (e) {
    console.error('[Mail.ru callback]', e.response?.data ?? e.message);
    res.redirect('/?error=mailru_auth_failed');
  }
});

// ─────────────────────────────────────────────
// AUTH ME
// ─────────────────────────────────────────────
app.get('/auth/me', requireAuth, (req, res) => {
  res.json({
    userId:   req.user.sub,
    email:    req.user.email    || null,
    provider: req.user.provider,
    name:     req.user.name     || null,
    avatar:   req.user.avatar   || null,
  });
});

// ─────────────────────────────────────────────
// REFRESH
// ─────────────────────────────────────────────
app.post('/auth/refresh', refreshLimiter, (req, res) => {
  const rt = req.cookies.refreshToken;
  if (!rt) return res.status(401).json({ error: 'Refresh token не передан' });
  if (revokedTokens.has(rt)) return res.status(401).json({ error: 'Refresh token отозван' });

  try {
    const d = jwt.verify(rt, process.env.JWT_SECRET);
    if (d.type !== 'refresh') return res.status(403).json({ error: 'Неверный тип токена' });

    const tokens = issueTokens({ id: d.sub, email: d.email, provider: d.provider, name: d.name, avatar: d.avatar });
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_COOKIE);
    res.json({ accessToken: tokens.accessToken });
  } catch (e) {
    const expired = e.name === 'TokenExpiredError';
    res.status(403).json({ error: expired ? 'Refresh token истёк' : 'Недействительный refresh token' });
  }
});

// ─────────────────────────────────────────────
// LOGOUT
// ─────────────────────────────────────────────
app.post('/auth/logout', requireAuth, (req, res) => {
  revokedTokens.add(req.token);
  res.clearCookie('refreshToken');
  res.json({ message: 'Выход выполнен' });
});

// ─────────────────────────────────────────────
// PROTECTED (демо)
// ─────────────────────────────────────────────
app.get('/api/protected', requireAuth, (req, res) => {
  res.json({ message: 'Доступ разрешён', user: req.user });
});

// ─────────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Unhandled]', err.message);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ SSO запущен — порт ${PORT} | NODE_ENV=${process.env.NODE_ENV}`);
  console.log(`   VK  → ${process.env.VK_REDIRECT_URI}`);
  console.log(`   Ya  → ${process.env.YANDEX_REDIRECT_URI}`);
  console.log(`   MR  → ${process.env.MAILRU_REDIRECT_URI}`);
});