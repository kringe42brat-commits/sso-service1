'use strict';
const express    = require('express');
const axios      = require('axios');
const jwt        = require('jsonwebtoken');
const cookieParse= require('cookie-parser');
const cors       = require('cors');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'"],
      scriptSrcAttr: ["'none'"],
      styleSrc:      ["'self'","'unsafe-inline'","https://fonts.googleapis.com"],
      fontSrc:       ["'self'","https://fonts.gstatic.com"],
      imgSrc:        ["'self'","data:","https:","blob:"],
      connectSrc:    ["'self'"],
      objectSrc:     ["'none'"],
      baseUri:       ["'none'"],
      frameAncestors:["'none'"],
    },
  },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

app.use(cors({ origin: process.env.FRONTEND_URL || 'https://sso-service1.onrender.com', credentials: true }));
app.use(cookieParse());
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// ── ENV ─────────────────────────────────────────────────────────────────────
const REQUIRED = ['JWT_SECRET','FRONTEND_URL',
  'VK_CLIENT_ID','VK_CLIENT_SECRET','VK_REDIRECT_URI',
  'YANDEX_CLIENT_ID','YANDEX_CLIENT_SECRET','YANDEX_REDIRECT_URI',
  'MAILRU_CLIENT_ID','MAILRU_CLIENT_SECRET','MAILRU_REDIRECT_URI'];
for (const k of REQUIRED) { if (!process.env[k]) { console.error(`[FATAL] Missing: ${k}`); process.exit(1); } }
if (process.env.JWT_SECRET.length < 32) { console.error('[FATAL] JWT_SECRET too short'); process.exit(1); }

const ACCESS_SECRET  = process.env.ACCESS_TOKEN_SECRET  || process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET + '_r';
const JWT_ISS = 'sso-service', JWT_AUD = 'sso-client';

// ── RATE LIMIT ───────────────────────────────────────────────────────────────
const authLimiter    = rateLimit({ windowMs:15*60*1000, max:30, standardHeaders:true, legacyHeaders:false });
const refreshLimiter = rateLimit({ windowMs:5*60*1000,  max:10, standardHeaders:true, legacyHeaders:false });

// ── HTTP CLIENT ──────────────────────────────────────────────────────────────
const http = axios.create({ timeout: 12000, headers: { 'User-Agent': 'SSO-Service/2.0' } });

// ── PKCE ─────────────────────────────────────────────────────────────────────
const genVerifier  = () => crypto.randomBytes(64).toString('base64url');
const genChallenge = v  => crypto.createHash('sha256').update(v).digest('base64url');
const genState     = () => crypto.randomBytes(32).toString('hex');

// ── COOKIES ──────────────────────────────────────────────────────────────────
const isProd = process.env.NODE_ENV === 'production';
const AUTH_C    = { httpOnly:true, secure:isProd, sameSite:'lax', maxAge:10*60*1000,       path:'/' };
const REFRESH_C = { httpOnly:true, secure:isProd, sameSite:'lax', maxAge:7*24*3600*1000,   path:'/' };
const clearRt   = res => res.clearCookie('refreshToken', { httpOnly:true, secure:isProd, sameSite:'lax', path:'/' });

// ── BLACKLIST ─────────────────────────────────────────────────────────────────
const revokedJtis = new Set();
setInterval(() => { if (revokedJtis.size > 10000) revokedJtis.clear(); }, 15*60*1000);

// ── SANITIZE ─────────────────────────────────────────────────────────────────
const str = (v, max) => (typeof v === 'string' ? v.slice(0, max).trim() || null : null);
const avatar = url => {
  if (typeof url !== 'string' || !url.startsWith('https://') || url.length > 512) return null;
  try {
    const h = new URL(url).hostname;
    if (!['avatars.yandex.net','userapi.com','vk.com','img.imgsmail.ru','filin.vkuser','st.mycdn.me','cdn.jsdelivr.net'].some(d => h.includes(d))) return null;
  } catch { return null; }
  return url;
};

// ── JWT ───────────────────────────────────────────────────────────────────────
function issueTokens(u) {
  const base = { sub: u.id, email: str(u.email,320), provider: str(u.provider,32), name: str(u.name,128), av: avatar(u.avatar) };
  return {
    accessToken:  jwt.sign({ ...base, jti: crypto.randomUUID() }, ACCESS_SECRET,  { expiresIn:'15m', issuer:JWT_ISS, audience:JWT_AUD, algorithm:'HS256' }),
    refreshToken: jwt.sign({ ...base, jti: crypto.randomUUID(), type:'refresh' },  REFRESH_SECRET, { expiresIn:'7d',  issuer:JWT_ISS, audience:JWT_AUD, algorithm:'HS256' }),
  };
}

const verifyAcc = t => jwt.verify(t, ACCESS_SECRET,  { algorithms:['HS256'], issuer:JWT_ISS, audience:JWT_AUD });
const verifyRef = t => jwt.verify(t, REFRESH_SECRET, { algorithms:['HS256'], issuer:JWT_ISS, audience:JWT_AUD });

function requireAuth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ','').trim();
  if (!t) return res.status(401).json({ error:'Токен не передан' });
  try {
    const d = verifyAcc(t);
    if (revokedJtis.has(d.jti)) return res.status(401).json({ error:'Токен отозван' });
    req.user = d; req.token = t; next();
  } catch(e) {
    res.status(e.name==='TokenExpiredError'?401:403).json({ error: e.name==='TokenExpiredError'?'Токен истёк':'Недействительный токен' });
  }
}

function requireXHR(req, res, next) {
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') return res.status(403).json({ error:'CSRF check failed' });
  next();
}

// ── HEALTH ───────────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status:'ok', uptime:Math.floor(process.uptime()), providers:['vk','yandex','mailru'] }));

// ── VK ID ────────────────────────────────────────────────────────────────────
app.get('/auth/vk', authLimiter, (req, res) => {
  const verifier = genVerifier(), state = genState();
  res.cookie('vk_auth', JSON.stringify({ state, verifier }), AUTH_C);
  const u = new URL('https://id.vk.com/authorize');
  u.searchParams.set('client_id',            process.env.VK_CLIENT_ID);
  u.searchParams.set('redirect_uri',         process.env.VK_REDIRECT_URI);
  u.searchParams.set('response_type',        'code');
  u.searchParams.set('scope',                'email');
  u.searchParams.set('state',                state);
  u.searchParams.set('code_challenge',       genChallenge(verifier));
  u.searchParams.set('code_challenge_method','S256');
  res.json({ authUrl: u.toString() });
});

app.get('/auth/vk/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const raw = req.cookies.vk_auth;
    res.clearCookie('vk_auth', { path:'/' });

    if (!code || typeof code !== 'string') return res.redirect('/#error=invalid_code');
    if (!raw) return res.redirect('/#error=invalid_state');
    let saved; try { saved = JSON.parse(raw); } catch { return res.redirect('/#error=invalid_state'); }
    if (state !== saved.state || !saved.verifier) return res.redirect('/#error=invalid_state');

    // Обмен кода на токен
    const { data: td } = await http.post('https://id.vk.com/oauth2/auth', null, {
      params: { grant_type:'authorization_code', code, client_id:process.env.VK_CLIENT_ID, client_secret:process.env.VK_CLIENT_SECRET, redirect_uri:process.env.VK_REDIRECT_URI, code_verifier:saved.verifier },
    });
    if (!td.access_token) throw new Error('VK: no access_token — ' + JSON.stringify(td));

    // ИСПРАВЛЕНО: используем api.vk.com вместо id.vk.com/oauth2/user_info
    const { data: apiData } = await http.get('https://api.vk.com/method/users.get', {
      params: { access_token: td.access_token, user_ids: td.user_id, fields: 'photo_200', v: '5.199' },
    });
    const vk = apiData?.response?.[0];
    if (!vk) throw new Error('VK: empty users.get response: ' + JSON.stringify(apiData));

    const tokens = issueTokens({
      id: `vk_${vk.id}`, provider:'vk',
      email:  td.email || null,
      name:   [vk.first_name, vk.last_name].filter(Boolean).join(' ') || null,
      avatar: vk.photo_200 || null,
    });
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_C);
    res.redirect(`/#token=${tokens.accessToken}`);
  } catch(e) {
    console.error('[VK callback]', e.response?.data ?? e.message);
    res.redirect('/#error=vk_auth_failed');
  }
});

// ── YANDEX ───────────────────────────────────────────────────────────────────
app.get('/auth/yandex', authLimiter, (req, res) => {
  const state = genState();
  res.cookie('ya_auth', state, AUTH_C);
  const u = new URL('https://oauth.yandex.ru/authorize');
  u.searchParams.set('client_id',    process.env.YANDEX_CLIENT_ID);
  u.searchParams.set('redirect_uri', process.env.YANDEX_REDIRECT_URI);
  u.searchParams.set('response_type','code');
  u.searchParams.set('state',        state);
  res.json({ authUrl: u.toString() });
});

app.get('/auth/yandex/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const saved = req.cookies.ya_auth;
    res.clearCookie('ya_auth', { path:'/' });
    if (!code || typeof code !== 'string') return res.redirect('/#error=invalid_code');
    if (!saved || state !== saved)         return res.redirect('/#error=invalid_state');

    const params = new URLSearchParams({ grant_type:'authorization_code', code, client_id:process.env.YANDEX_CLIENT_ID, client_secret:process.env.YANDEX_CLIENT_SECRET, redirect_uri:process.env.YANDEX_REDIRECT_URI });
    const { data: td } = await http.post('https://oauth.yandex.ru/token', params);
    if (!td.access_token) throw new Error('Yandex: no access_token');

    const { data: ya } = await http.get('https://login.yandex.ru/info', { headers:{ Authorization:`OAuth ${td.access_token}` }, params:{ format:'json' } });
    if (!ya.id) throw new Error('Yandex: no user id');

    const tokens = issueTokens({
      id: `yandex_${ya.id}`, provider:'yandex',
      email:  ya.default_email || ya.emails?.[0] || null,
      name:   ya.display_name || ya.real_name || ya.login || null,
      avatar: ya.default_avatar_id ? `https://avatars.yandex.net/get-yapic/${ya.default_avatar_id}/islands-200` : null,
    });
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_C);
    res.redirect(`/#token=${tokens.accessToken}`);
  } catch(e) {
    console.error('[Yandex callback]', e.response?.data ?? e.message);
    res.redirect('/#error=yandex_auth_failed');
  }
});

// ── MAIL.RU ───────────────────────────────────────────────────────────────────
app.get('/auth/mailru', authLimiter, (req, res) => {
  const state = genState();
  res.cookie('mr_auth', state, AUTH_C);
  const u = new URL('https://connect.mail.ru/oauth/authorize');
  u.searchParams.set('client_id',    process.env.MAILRU_CLIENT_ID);
  u.searchParams.set('redirect_uri', process.env.MAILRU_REDIRECT_URI);
  u.searchParams.set('response_type','code');
  u.searchParams.set('scope',        'userinfo');
  u.searchParams.set('state',        state);
  res.json({ authUrl: u.toString() });
});

app.get('/auth/mailru/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const saved = req.cookies.mr_auth;
    res.clearCookie('mr_auth', { path:'/' });
    if (!code || typeof code !== 'string') return res.redirect('/#error=invalid_code');
    if (!saved || state !== saved)         return res.redirect('/#error=invalid_state');

    const params = new URLSearchParams({ grant_type:'authorization_code', code, client_id:process.env.MAILRU_CLIENT_ID, client_secret:process.env.MAILRU_CLIENT_SECRET, redirect_uri:process.env.MAILRU_REDIRECT_URI });
    const { data: td } = await http.post('https://connect.mail.ru/oauth/token', params);
    if (!td.access_token) throw new Error('Mail.ru: no access_token');

    // ИСПРАВЛЕНО: access_token как query-параметр (более надёжно чем Bearer для Mail.ru)
    let mu;
    try {
      const r1 = await http.get('https://oauth.mail.ru/userinfo', { params: { access_token: td.access_token } });
      mu = r1.data;
    } catch {
      // fallback: Bearer header
      const r2 = await http.get('https://oauth.mail.ru/userinfo', { headers: { Authorization: `Bearer ${td.access_token}` } });
      mu = r2.data;
    }
    if (!mu || !mu.id) throw new Error('Mail.ru: empty userinfo — ' + JSON.stringify(mu));

    const tokens = issueTokens({
      id: `mailru_${mu.id}`, provider:'mailru',
      email:  mu.email || null,
      name:   mu.name  || null,
      avatar: mu.image || null,
    });
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_C);
    res.redirect(`/#token=${tokens.accessToken}`);
  } catch(e) {
    console.error('[Mail.ru callback]', e.response?.data ?? e.message);
    res.redirect('/#error=mailru_auth_failed');
  }
});

// ── AUTH ME ───────────────────────────────────────────────────────────────────
app.get('/auth/me', requireAuth, (req, res) => res.json({
  userId: req.user.sub, email: req.user.email||null,
  provider: req.user.provider, name: req.user.name||null, avatar: req.user.av||null,
}));

// ── REFRESH ───────────────────────────────────────────────────────────────────
app.post('/auth/refresh', refreshLimiter, requireXHR, (req, res) => {
  const rt = req.cookies.refreshToken;
  if (!rt) return res.status(401).json({ error:'Нет refresh token' });
  try {
    const d = verifyRef(rt);
    if (d.type !== 'refresh') return res.status(403).json({ error:'Неверный тип' });
    if (revokedJtis.has(d.jti)) return res.status(401).json({ error:'Отозван' });
    const tokens = issueTokens({ id:d.sub, email:d.email, provider:d.provider, name:d.name, avatar:d.av });
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_C);
    res.json({ accessToken: tokens.accessToken });
  } catch(e) {
    clearRt(res);
    res.status(403).json({ error:'Недействительный refresh token' });
  }
});

// ── LOGOUT ────────────────────────────────────────────────────────────────────
app.post('/auth/logout', requireAuth, requireXHR, (req, res) => {
  if (req.user.jti) revokedJtis.add(req.user.jti);
  const rt = req.cookies.refreshToken;
  if (rt) { try { const d = verifyRef(rt); if (d.jti) revokedJtis.add(d.jti); } catch {} }
  clearRt(res);
  res.json({ message:'Выход выполнен' });
});

app.use((err, req, res, next) => { console.error('[ERR]', err.message); res.status(500).json({ error:'Ошибка сервера' }); });

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ SSO на порту ${PORT} | prod=${isProd}`);
  console.log(`   VK  callback: ${process.env.VK_REDIRECT_URI}`);
  console.log(`   Ya  callback: ${process.env.YANDEX_REDIRECT_URI}`);
  console.log(`   MR  callback: ${process.env.MAILRU_REDIRECT_URI}`);
});
