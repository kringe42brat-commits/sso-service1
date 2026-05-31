'use strict';
const express    = require('express');
const axios      = require('axios');
const jwt        = require('jsonwebtoken');
const cookieParse= require('cookie-parser');
const cors       = require('cors');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const path       = require('path');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc:["'self'"], scriptSrc:["'self'"], scriptSrcAttr:["'none'"],
    styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],
    fontSrc:["'self'","https://fonts.gstatic.com"],
    imgSrc:["'self'","data:","https:","blob:"],
    connectSrc:["'self'"], objectSrc:["'none'"], baseUri:["'none'"], frameAncestors:["'none'"],
  }},
  referrerPolicy:{ policy:'no-referrer' },
  hsts:{ maxAge:31536000, includeSubDomains:true },
}));

app.use(cors({ origin: process.env.FRONTEND_URL||'https://sso-service1.onrender.com', credentials:true }));
app.use(cookieParse());
app.use(express.json({ limit:'10kb' }));
app.use(express.static('public'));

// ── ENV ──────────────────────────────────────────────────────────────────────
const REQ=['JWT_SECRET','FRONTEND_URL','VK_CLIENT_ID','VK_CLIENT_SECRET','VK_REDIRECT_URI','YANDEX_CLIENT_ID','YANDEX_CLIENT_SECRET','YANDEX_REDIRECT_URI','MAILRU_CLIENT_ID','MAILRU_CLIENT_SECRET','MAILRU_REDIRECT_URI'];
for (const k of REQ) { if (!process.env[k]) { console.error(`[FATAL] Missing: ${k}`); process.exit(1); } }
if (process.env.JWT_SECRET.length<32) { console.error('[FATAL] JWT_SECRET too short'); process.exit(1); }

const ACC_SEC = process.env.ACCESS_TOKEN_SECRET  || process.env.JWT_SECRET;
const REF_SEC = process.env.REFRESH_TOKEN_SECRET || process.env.JWT_SECRET+'_r';
const ISS='sso-service', AUD='sso-client';

const authLimiter    = rateLimit({ windowMs:15*60*1000, max:30, standardHeaders:true, legacyHeaders:false });
const refreshLimiter = rateLimit({ windowMs:5*60*1000,  max:10, standardHeaders:true, legacyHeaders:false });

const FORM_HEADERS = { 'Content-Type':'application/x-www-form-urlencoded' };
const http = axios.create({ timeout:15000, headers:{ 'User-Agent':'SSO-Service/2.0' } });

const genVerifier  = () => crypto.randomBytes(64).toString('base64url');
const genChallenge = v  => crypto.createHash('sha256').update(v).digest('base64url');
const genState     = () => crypto.randomBytes(32).toString('hex');

const isProd    = process.env.NODE_ENV==='production';
const AUTH_C    = { httpOnly:true, secure:isProd, sameSite:'lax', maxAge:10*60*1000,     path:'/' };
const REFRESH_C = { httpOnly:true, secure:isProd, sameSite:'lax', maxAge:7*24*3600*1000, path:'/' };
const clearRt   = res => res.clearCookie('refreshToken',{ httpOnly:true, secure:isProd, sameSite:'lax', path:'/' });

const revokedJtis = new Set();
setInterval(()=>{ if(revokedJtis.size>10000) revokedJtis.clear(); }, 15*60*1000);

const trim      = (v,n) => typeof v==='string' ? v.slice(0,n).trim()||null : null;
const safeAvatar= url => {
  if (typeof url!=='string'||!url.startsWith('https://')||url.length>512) return null;
  try { new URL(url); return url; } catch { return null; }
};

function issueTokens(u) {
  const base={ sub:u.id, email:trim(u.email,320), provider:trim(u.provider,32), name:trim(u.name,128), av:safeAvatar(u.avatar) };
  return {
    accessToken:  jwt.sign({...base,jti:crypto.randomUUID()}, ACC_SEC, {expiresIn:'15m',issuer:ISS,audience:AUD,algorithm:'HS256'}),
    refreshToken: jwt.sign({...base,jti:crypto.randomUUID(),type:'refresh'}, REF_SEC, {expiresIn:'7d',issuer:ISS,audience:AUD,algorithm:'HS256'}),
  };
}
const verifyAcc = t => jwt.verify(t, ACC_SEC, {algorithms:['HS256'],issuer:ISS,audience:AUD});
const verifyRef = t => jwt.verify(t, REF_SEC, {algorithms:['HS256'],issuer:ISS,audience:AUD});

function requireAuth(req,res,next){
  const t=(req.headers.authorization||'').replace('Bearer ','').trim();
  if (!t) return res.status(401).json({error:'Нет токена'});
  try { const d=verifyAcc(t); if(revokedJtis.has(d.jti)) return res.status(401).json({error:'Отозван'}); req.user=d; req.token=t; next(); }
  catch(e){ res.status(e.name==='TokenExpiredError'?401:403).json({error:e.name==='TokenExpiredError'?'Истёк':'Недействителен'}); }
}
function requireXHR(req,res,next){ if(req.headers['x-requested-with']!=='XMLHttpRequest') return res.status(403).json({error:'CSRF'}); next(); }

function redirectError(res, code, detail) {
  console.error(`[ERROR:${code}]`, detail);
  return res.redirect(`/?auth_error=${encodeURIComponent(code)}&detail=${encodeURIComponent(String(detail).slice(0,200))}`);
}

// ── HELPER для редиректа после успешного входа ──────────────────────────────
function finalRedirect(res, accessToken, redirectPath) {
  let target = redirectPath || process.env.FRONTEND_URL || '/';
  // убедимся, что это относительный путь или разрешённый домен
  if (target.startsWith('/')) {
    // относительный – безопасно
    res.redirect(`${target}?token=${accessToken}`);
  } else {
    // абсолютный – проверяем, что это наш фронтенд или доверенный
    const allowed = [process.env.FRONTEND_URL, process.env.DEMO_URL].filter(Boolean);
    let ok = false;
    for (const a of allowed) {
      if (target.startsWith(a)) { ok = true; break; }
    }
    if (ok) res.redirect(`${target}${target.includes('?')?'&':'?'}token=${accessToken}`);
    else res.redirect(`/?token=${accessToken}`);
  }
}

app.get('/health', (_,res)=>res.json({status:'ok',uptime:Math.floor(process.uptime()),providers:['vk','yandex','mailru']}));

// ════════════════════════════════════════════════════════════════
// VK ID
// ════════════════════════════════════════════════════════════════
app.get('/auth/vk', authLimiter, (req,res)=>{
  const verifier=genVerifier(), state=genState();
  const redirectTo = req.query.redirect || '/';
  res.cookie('vk_auth', JSON.stringify({state,verifier,redirectTo}), AUTH_C);
  const u=new URL('https://id.vk.com/authorize');
  u.searchParams.set('client_id',            process.env.VK_CLIENT_ID);
  u.searchParams.set('redirect_uri',         process.env.VK_REDIRECT_URI);
  u.searchParams.set('response_type',        'code');
  u.searchParams.set('scope',                'email');
  u.searchParams.set('state',                state);
  u.searchParams.set('code_challenge',       genChallenge(verifier));
  u.searchParams.set('code_challenge_method','S256');
  res.json({ authUrl: u.toString() });
});

app.get('/auth/vk/callback', async (req,res)=>{
  const {code, state, device_id}=req.query;
  const raw=req.cookies.vk_auth;
  res.clearCookie('vk_auth',{path:'/'});
  if (!code||typeof code!=='string') return redirectError(res,'invalid_code','no code param');
  if (!raw) return redirectError(res,'invalid_state','no vk_auth cookie');
  let saved; try { saved=JSON.parse(raw); } catch(e) { return redirectError(res,'invalid_state','cookie parse error: '+e.message); }
  if (!state||state!==saved.state||!saved.verifier) return redirectError(res,'invalid_state',`state mismatch`);
  const redirectPath = saved.redirectTo || '/';
  try {
    const tokenBody = new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      client_id:     process.env.VK_CLIENT_ID,
      client_secret: process.env.VK_CLIENT_SECRET,
      redirect_uri:  process.env.VK_REDIRECT_URI,
      code_verifier: saved.verifier,
      ...(device_id ? { device_id } : {}),
    });
    const {data:td} = await http.post('https://id.vk.com/oauth2/auth', tokenBody.toString(), { headers: FORM_HEADERS });
    if (!td.access_token) return redirectError(res,'vk_auth_failed','no access_token: '+JSON.stringify(td));
    const userId = td.user_id || td.userId;
    if (!userId) return redirectError(res,'vk_auth_failed','no user_id in token response');
    let name=null, avatar=null;
    try {
      const {data:a}=await http.get('https://api.vk.com/method/users.get',{
        params:{ access_token:td.access_token, user_ids:userId, fields:'photo_200', v:'5.131' },
      });
      const u=a?.response?.[0];
      if (u) { name=[u.first_name,u.last_name].filter(Boolean).join(' ')||null; avatar=u.photo_200||null; }
    } catch(e) { console.warn('[VK] api.vk.com failed:',e.message); }
    if (!name) {
      try {
        const {data:b}=await http.post('https://id.vk.com/oauth2/user_info', new URLSearchParams({access_token:td.access_token, client_id:process.env.VK_CLIENT_ID}).toString(), { headers: FORM_HEADERS });
        const u=b?.user;
        if (u) { name=[u.first_name,u.last_name].filter(Boolean).join(' ')||null; avatar=u.avatar||null; }
      } catch(e) { console.warn('[VK] user_info failed:',e.message); }
    }
    const tokens=issueTokens({id:`vk_${userId}`, provider:'vk', email:td.email||null, name, avatar});
    res.cookie('refreshToken', tokens.refreshToken, REFRESH_C);
    finalRedirect(res, tokens.accessToken, redirectPath);
  } catch(e) {
    redirectError(res,'vk_auth_failed', e.response?.data ? JSON.stringify(e.response.data) : e.message);
  }
});

// ════════════════════════════════════════════════════════════════
// YANDEX
// ════════════════════════════════════════════════════════════════
app.get('/auth/yandex', authLimiter, (req,res)=>{
  const state=genState();
  const redirectTo = req.query.redirect || '/';
  res.cookie('ya_auth', JSON.stringify({state, redirectTo}), AUTH_C);
  const u=new URL('https://oauth.yandex.ru/authorize');
  u.searchParams.set('client_id',    process.env.YANDEX_CLIENT_ID);
  u.searchParams.set('redirect_uri', process.env.YANDEX_REDIRECT_URI);
  u.searchParams.set('response_type','code');
  u.searchParams.set('state',        state);
  res.json({ authUrl: u.toString() });
});

app.get('/auth/yandex/callback', async (req,res)=>{
  const {code,state}=req.query;
  const raw=req.cookies.ya_auth;
  res.clearCookie('ya_auth',{path:'/'});
  if (!code||typeof code!=='string') return redirectError(res,'invalid_code','no code');
  if (!raw) return redirectError(res,'invalid_state','no ya_auth cookie');
  let saved; try { saved=JSON.parse(raw); } catch(e) { return redirectError(res,'invalid_state','cookie parse'); }
  if (!saved.state || state!==saved.state) return redirectError(res,'invalid_state','state mismatch');
  const redirectPath = saved.redirectTo || '/';
  try {
    const tokenBody=new URLSearchParams({grant_type:'authorization_code',code,client_id:process.env.YANDEX_CLIENT_ID,client_secret:process.env.YANDEX_CLIENT_SECRET,redirect_uri:process.env.YANDEX_REDIRECT_URI});
    const {data:td}=await http.post('https://oauth.yandex.ru/token', tokenBody.toString(), {headers:FORM_HEADERS});
    if (!td.access_token) throw new Error('no access_token: '+JSON.stringify(td));
    const {data:ya}=await http.get('https://login.yandex.ru/info',{headers:{Authorization:`OAuth ${td.access_token}`},params:{format:'json'}});
    if (!ya.id) throw new Error('no user id');
    const tokens=issueTokens({
      id:`yandex_${ya.id}`, provider:'yandex',
      email: ya.default_email||ya.emails?.[0]||null,
      name:  ya.display_name||ya.real_name||ya.login||null,
      avatar:ya.default_avatar_id?`https://avatars.yandex.net/get-yapic/${ya.default_avatar_id}/islands-200`:null,
    });
    res.cookie('refreshToken',tokens.refreshToken,REFRESH_C);
    finalRedirect(res, tokens.accessToken, redirectPath);
  } catch(e){ redirectError(res,'yandex_auth_failed', e.response?.data?JSON.stringify(e.response.data):e.message); }
});

// ════════════════════════════════════════════════════════════════
// MAIL.RU
// ════════════════════════════════════════════════════════════════
app.get('/auth/mailru', authLimiter, (req,res)=>{
  const state=genState();
  const redirectTo = req.query.redirect || '/';
  res.cookie('mr_auth', JSON.stringify({state, redirectTo}), AUTH_C);
  const u=new URL('https://connect.mail.ru/oauth/authorize');
  u.searchParams.set('client_id',    process.env.MAILRU_CLIENT_ID);
  u.searchParams.set('redirect_uri', process.env.MAILRU_REDIRECT_URI);
  u.searchParams.set('response_type','code');
  u.searchParams.set('scope',        'userinfo');
  u.searchParams.set('state',        state);
  res.json({ authUrl: u.toString() });
});

app.get('/auth/mailru/callback', async (req,res)=>{
  const {code,state}=req.query;
  const raw=req.cookies.mr_auth;
  res.clearCookie('mr_auth',{path:'/'});
  if (!code||typeof code!=='string') return redirectError(res,'invalid_code','no code');
  if (!raw) return redirectError(res,'invalid_state','no mr_auth cookie');
  let saved; try { saved=JSON.parse(raw); } catch(e) { return redirectError(res,'invalid_state','cookie parse'); }
  if (!saved.state || state!==saved.state) return redirectError(res,'invalid_state','state mismatch');
  const redirectPath = saved.redirectTo || '/';
  try {
    const tokenBody=new URLSearchParams({
      grant_type:'authorization_code', code,
      client_id:process.env.MAILRU_CLIENT_ID,
      client_secret:process.env.MAILRU_CLIENT_SECRET,
      redirect_uri:process.env.MAILRU_REDIRECT_URI,
    });
    const {data:td}=await http.post('https://connect.mail.ru/oauth/token', tokenBody.toString(), {headers:FORM_HEADERS});
    if (!td.access_token) return redirectError(res,'mailru_auth_failed','no access_token: '+JSON.stringify(td));
    const apiParams = {
      app_id:      process.env.MAILRU_CLIENT_ID,
      method:      'users.getInfo',
      secure:      '1',
      session_key: td.access_token,
    };
    const sigStr = Object.keys(apiParams).sort().map(k=>`${k}=${apiParams[k]}`).join('') + process.env.MAILRU_CLIENT_SECRET;
    const sig = crypto.createHash('md5').update(sigStr).digest('hex');
    const {data:muArr}=await http.get('https://www.appsmail.ru/platform/api', { params:{...apiParams, sig} });
    const mu = Array.isArray(muArr) ? muArr[0] : muArr;
    if (!mu?.uid && !mu?.email) return redirectError(res,'mailru_auth_failed','empty platform response: '+JSON.stringify(mu));
    const userId = mu.uid || td.x_mailru_vid || mu.id;
    const tokens=issueTokens({
      id:`mailru_${userId}`,
      provider:'mailru',
      email:  mu.email || td.email || null,
      name:   [mu.first_name,mu.last_name].filter(Boolean).join(' ') || mu.nick || null,
      avatar: mu.pic_190 || mu.pic_big || mu.pic || null,
    });
    res.cookie('refreshToken',tokens.refreshToken,REFRESH_C);
    finalRedirect(res, tokens.accessToken, redirectPath);
  } catch(e){ redirectError(res,'mailru_auth_failed', e.response?.data?JSON.stringify(e.response.data):e.message); }
});

// ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────
app.get('/auth/me', requireAuth, (req,res)=>res.json({
  userId:req.user.sub, email:req.user.email||null,
  provider:req.user.provider, name:req.user.name||null, avatar:req.user.av||null,
}));

app.post('/auth/refresh', refreshLimiter, requireXHR, (req,res)=>{
  const rt=req.cookies.refreshToken;
  if (!rt) return res.status(401).json({error:'Нет refresh token'});
  try {
    const d=verifyRef(rt);
    if (d.type!=='refresh'||revokedJtis.has(d.jti)) return res.status(401).json({error:'Недействителен'});
    const tokens=issueTokens({id:d.sub,email:d.email,provider:d.provider,name:d.name,avatar:d.av});
    res.cookie('refreshToken',tokens.refreshToken,REFRESH_C);
    res.json({accessToken:tokens.accessToken});
  } catch { clearRt(res); res.status(403).json({error:'Ошибка refresh'}); }
});

app.post('/auth/logout', requireAuth, requireXHR, (req,res)=>{
  if (req.user.jti) revokedJtis.add(req.user.jti);
  const rt=req.cookies.refreshToken;
  if (rt) { try{ const d=verifyRef(rt); if(d.jti) revokedJtis.add(d.jti); }catch{} }
  clearRt(res); res.json({message:'Выход выполнен'});
});

// ── ДЕМО-САЙТ (второй сайт) ─────────────────────────────────────────────────
app.get('/demo', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'demo.html'));
});
// Статические файлы для демо (можно и встроить скрипт, но для порядка положим JS отдельно)
app.use(express.static('public'));

app.use((err,req,res,next)=>{ console.error('[ERR]',err.message); res.status(500).json({error:'Ошибка сервера'}); });

const PORT=process.env.PORT||3001;
app.listen(PORT,'0.0.0.0',()=>{
  console.log(`✅ SSO порт ${PORT} | prod=${isProd}`);
  console.log(`   VK: ${process.env.VK_REDIRECT_URI}`);
  console.log(`   Ya: ${process.env.YANDEX_REDIRECT_URI}`);
  console.log(`   MR: ${process.env.MAILRU_REDIRECT_URI}`);
});