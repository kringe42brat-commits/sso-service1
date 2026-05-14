const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(cors({ origin: process.env.FRONTEND_URL || 'https://sso-service1.onrender.com', credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Слишком много запросов.' } });
const refreshLimiter = rateLimit({ windowMs: 5*60*1000, max: 10, message: { error: 'Слишком много попыток.' } });
const axiosInstance = axios.create({ timeout: 10000 });

const requiredEnv = ['JWT_SECRET','VK_CLIENT_ID','VK_CLIENT_SECRET','VK_REDIRECT_URI','YANDEX_CLIENT_ID','YANDEX_CLIENT_SECRET','YANDEX_REDIRECT_URI','MAILRU_CLIENT_ID','MAILRU_CLIENT_SECRET','MAILRU_REDIRECT_URI','FRONTEND_URL'];
for (const k of requiredEnv) { if (!process.env[k]) { console.error(`❌ Отсутствует: ${k}`); process.exit(1); } }

// ====== PKCE ======
function genVerifier()   { return crypto.randomBytes(64).toString('base64url'); }
function genChallenge(v) { return crypto.createHash('sha256').update(v).digest('base64url'); }
function genState()      { return crypto.randomBytes(32).toString('hex'); }

// ====== Все временные данные хранятся в cookie — переживают перезапуск сервера ======
const COOKIE_OPTS = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 10 * 60 * 1000 };

// ====== JWT ======
const revokedTokens = new Set();
setInterval(() => { revokedTokens.forEach(t => { try { jwt.verify(t, process.env.JWT_SECRET); } catch { revokedTokens.delete(t); } }); }, 30*60*1000);

class UnifiedUser {
  constructor(provider, providerId, email, name, avatar) {
    this.provider = provider; this.providerId = String(providerId);
    this.email = email; this.name = name; this.avatar = avatar;
    this.id = `${provider}_${providerId}`;
  }
}

function generateTokens(user) {
  const p = { userId: user.id, email: user.email, provider: user.provider, name: user.name, avatar: user.avatar };
  return {
    accessToken:  jwt.sign(p, process.env.JWT_SECRET, { expiresIn: '15m' }),
    refreshToken: jwt.sign({ ...p, type: 'refresh' }, process.env.JWT_SECRET, { expiresIn: '7d' })
  };
}

const REFRESH_OPTS = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 7*24*60*60*1000 };

function authMiddleware(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Токен отсутствует' });
  if (revokedTokens.has(token)) return res.status(401).json({ error: 'Токен отозван' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(err.name === 'TokenExpiredError' ? 401 : 403).json({ error: err.name === 'TokenExpiredError' ? 'Токен истёк' : 'Недействительный токен' });
    req.user = user; req.token = token; next();
  });
}

// ====== HEALTH ======
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: Math.floor(process.uptime()), timestamp: new Date().toISOString(), providers: ['vk','yandex','mailru'] }));

// ====== VK ID (PKCE + state в cookie) ======
app.get('/auth/vk', authLimiter, (req, res) => {
  const verifier   = genVerifier();
  const challenge  = genChallenge(verifier);
  const state      = genState();

  res.cookie('vk_cv',    verifier, COOKIE_OPTS);
  res.cookie('vk_state', state,    COOKIE_OPTS);

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
    const savedState  = req.cookies.vk_state;
    const codeVerifier= req.cookies.vk_cv;

    res.clearCookie('vk_state'); res.clearCookie('vk_cv');

    if (!code)          return res.redirect('/?error=invalid_code');
    if (!savedState || state !== savedState) return res.redirect('/?error=invalid_state');
    if (!codeVerifier)  return res.redirect('/?error=invalid_state');

    const { data: td } = await axiosInstance.post('https://id.vk.com/oauth2/auth', null, {
      params: { grant_type: 'authorization_code', code, client_id: process.env.VK_CLIENT_ID, client_secret: process.env.VK_CLIENT_SECRET, redirect_uri: process.env.VK_REDIRECT_URI, code_verifier: codeVerifier }
    });

    const { data: ud } = await axiosInstance.get('https://id.vk.com/method/users.get', {
      params: { access_token: td.access_token, user_ids: td.user_id, fields: 'photo_200,first_name,last_name' }
    });

    const vk = ud?.response?.[0];
    if (!vk) throw new Error('no user');

    const user = new UnifiedUser('vk', vk.id, td.email || `${vk.id}@vk.com`, `${vk.first_name} ${vk.last_name}`, vk.photo_200);
    const tokens = generateTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_OPTS);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch(e) {
    console.error('VK callback error:', e.response?.data || e.message);
    res.redirect('/?error=vk_auth_failed');
  }
});

// ====== ЯНДЕКС (state в cookie) ======
app.get('/auth/yandex', authLimiter, (req, res) => {
  const state = genState();
  res.cookie('ya_state', state, COOKIE_OPTS);

  const url = new URL('https://oauth.yandex.ru/authorize');
  url.searchParams.set('client_id',    process.env.YANDEX_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.YANDEX_REDIRECT_URI);
  url.searchParams.set('response_type','code');
  url.searchParams.set('state',        state);
  res.json({ authUrl: url.toString() });
});

app.get('/auth/yandex/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const saved = req.cookies.ya_state;
    res.clearCookie('ya_state');
    if (!code)                   return res.redirect('/?error=invalid_code');
    if (!saved || state !== saved) return res.redirect('/?error=invalid_state');

    const params = new URLSearchParams({ grant_type:'authorization_code', code, client_id: process.env.YANDEX_CLIENT_ID, client_secret: process.env.YANDEX_CLIENT_SECRET, redirect_uri: process.env.YANDEX_REDIRECT_URI });
    const { data: td } = await axiosInstance.post('https://oauth.yandex.ru/token', params);
    const { data: ya } = await axiosInstance.get('https://login.yandex.ru/info', { headers:{ Authorization:`OAuth ${td.access_token}` }, params:{ format:'json' } });

    const user = new UnifiedUser('yandex', ya.id, ya.default_email || `${ya.id}@yandex.ru`, ya.display_name || ya.real_name || ya.login || 'Yandex User', ya.default_avatar_id ? `https://avatars.yandex.net/get-yapic/${ya.default_avatar_id}/islands-200` : null);
    const tokens = generateTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_OPTS);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch(e) {
    console.error('Yandex callback error:', e.response?.data || e.message);
    res.redirect('/?error=yandex_auth_failed');
  }
});

// ====== MAIL.RU (state в cookie) ======
app.get('/auth/mailru', authLimiter, (req, res) => {
  const state = genState();
  res.cookie('mr_state', state, COOKIE_OPTS);

  const url = new URL('https://connect.mail.ru/oauth/authorize');
  url.searchParams.set('client_id',    process.env.MAILRU_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.MAILRU_REDIRECT_URI);
  url.searchParams.set('response_type','code');
  url.searchParams.set('scope',        'userinfo');
  url.searchParams.set('state',        state);
  res.json({ authUrl: url.toString() });
});

app.get('/auth/mailru/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const saved = req.cookies.mr_state;
    res.clearCookie('mr_state');
    if (!code)                   return res.redirect('/?error=invalid_code');
    if (!saved || state !== saved) return res.redirect('/?error=invalid_state');

    const params = new URLSearchParams({ grant_type:'authorization_code', code, client_id: process.env.MAILRU_CLIENT_ID, client_secret: process.env.MAILRU_CLIENT_SECRET, redirect_uri: process.env.MAILRU_REDIRECT_URI });
    const { data: td } = await axiosInstance.post('https://connect.mail.ru/oauth/token', params);
    const { data: mu } = await axiosInstance.get('https://www.appsmail.ru/platform/api', { params:{ method:'users.getInfo', app_id: process.env.MAILRU_CLIENT_ID, session_key: td.access_token, secure:1 } });
    if (!mu[0]) throw new Error('no user');

    const user = new UnifiedUser('mailru', mu[0].uid, mu[0].email, `${mu[0].first_name} ${mu[0].last_name}`, mu[0].pic_50 || mu[0].pic_big);
    const tokens = generateTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_OPTS);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch(e) {
    console.error('Mail.ru callback error:', e.response?.data || e.message);
    res.redirect('/?error=mailru_auth_failed');
  }
});

// ====== AUTH ME / REFRESH / LOGOUT ======
app.get('/auth/me', authMiddleware, (req, res) => res.json({ userId: req.user.userId, email: req.user.email, provider: req.user.provider, name: req.user.name||null, avatar: req.user.avatar||null }));

app.post('/auth/refresh', refreshLimiter, (req, res) => {
  const rt = req.cookies.refreshToken;
  if (!rt) return res.status(401).json({ error: 'Refresh token отсутствует' });
  if (revokedTokens.has(rt)) return res.status(401).json({ error: 'Refresh token отозван' });
  try {
    const d = jwt.verify(rt, process.env.JWT_SECRET);
    if (d.type !== 'refresh') throw new Error();
    const tokens = generateTokens({ id: d.userId, email: d.email, provider: d.provider, name: d.name, avatar: d.avatar });
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_OPTS);
    res.json({ accessToken: tokens.accessToken });
  } catch { res.status(403).json({ error: 'Недействительный refresh token' }); }
});

app.post('/auth/logout', authMiddleware, (req, res) => {
  revokedTokens.add(req.token);
  res.clearCookie('refreshToken');
  res.json({ message: 'Выход выполнен' });
});

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); });

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ SSO запущен на порту ${PORT}`));
