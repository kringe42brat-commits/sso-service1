cat > /mnt/user-data/outputs/index.js << 'EOF'
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

// ====== БЕЗОПАСНОСТЬ ======
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

app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://sso-service1.onrender.com',
  credentials: true
}));

app.use(cookieParser());
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// ====== RATE LIMITING ======
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Слишком много запросов. Попробуйте через 15 минут.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const refreshLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  message: { error: 'Слишком много попыток обновления токена.' },
});

// ====== AXIOS С ТАЙМАУТОМ ======
const axiosInstance = axios.create({ timeout: 10000 });

// ====== ПРОВЕРКА ПЕРЕМЕННЫХ ОКРУЖЕНИЯ ======
const requiredEnv = [
  'JWT_SECRET',
  'VK_CLIENT_ID', 'VK_CLIENT_SECRET', 'VK_REDIRECT_URI',
  'YANDEX_CLIENT_ID', 'YANDEX_CLIENT_SECRET', 'YANDEX_REDIRECT_URI',
  'MAILRU_CLIENT_ID', 'MAILRU_CLIENT_SECRET', 'MAILRU_REDIRECT_URI',
  'FRONTEND_URL'
];
for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`❌ Отсутствует обязательная переменная: ${key}`);
    process.exit(1);
  }
}

// ====== CSRF STATE STORE (+ PKCE для VK) ======
const pendingStates = new Map(); // state -> { ts, codeVerifier }
setInterval(() => {
  const now = Date.now();
  pendingStates.forEach((val, state) => {
    if (now - val.ts > 10 * 60 * 1000) pendingStates.delete(state);
  });
}, 5 * 60 * 1000);

function generateState(extra = {}) {
  const state = crypto.randomBytes(32).toString('hex');
  pendingStates.set(state, { ts: Date.now(), ...extra });
  return state;
}

function validateState(state) {
  if (!state || !pendingStates.has(state)) return null;
  const data = pendingStates.get(state);
  pendingStates.delete(state);
  return data;
}

// ====== PKCE helpers ======
function generateCodeVerifier() {
  return crypto.randomBytes(64).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

// ====== IN-MEMORY ТОКЕН-БЛЭКЛИСТ ======
const revokedTokens = new Set();
setInterval(() => {
  revokedTokens.forEach(token => {
    try { jwt.verify(token, process.env.JWT_SECRET); }
    catch { revokedTokens.delete(token); }
  });
}, 30 * 60 * 1000);

// ====== УНИФИЦИРОВАННЫЙ ПОЛЬЗОВАТЕЛЬ ======
class UnifiedUser {
  constructor(provider, providerId, email, name, avatar) {
    this.provider = provider;
    this.providerId = String(providerId);
    this.email = email;
    this.name = name;
    this.avatar = avatar;
    this.id = `${provider}_${providerId}`;
  }
}

// ====== ГЕНЕРАЦИЯ JWT ======
function generateTokens(user) {
  const payload = { userId: user.id, email: user.email, provider: user.provider, name: user.name, avatar: user.avatar };
  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ ...payload, type: 'refresh' }, process.env.JWT_SECRET, { expiresIn: '7d' });
  return { accessToken, refreshToken };
}

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000
};

// ====== МИДДЛВАР ПРОВЕРКИ JWT ======
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Токен отсутствует' });
  if (revokedTokens.has(token)) return res.status(401).json({ error: 'Токен отозван' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Токен истёк' });
      return res.status(403).json({ error: 'Недействительный токен' });
    }
    req.user = user;
    req.token = token;
    next();
  });
}

// ====== HEALTH CHECK ======
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: Math.floor(process.uptime()), timestamp: new Date().toISOString(), providers: ['vk', 'yandex', 'mailru'] });
});

// ====== VK ID (с PKCE) ======
app.get('/auth/vk', authLimiter, (req, res) => {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = generateState({ codeVerifier });

  const url = new URL('https://id.vk.com/authorize');
  url.searchParams.set('client_id', process.env.VK_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.VK_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'email');
  url.searchParams.set('state', state);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  res.json({ authUrl: url.toString() });
});

app.get('/auth/vk/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || typeof code !== 'string') return res.redirect('/?error=invalid_code');

    const stateData = validateState(state);
    if (!stateData) return res.redirect('/?error=invalid_state');

    const tokenResponse = await axiosInstance.post('https://id.vk.com/oauth2/auth', null, {
      params: {
        grant_type: 'authorization_code',
        code,
        client_id: process.env.VK_CLIENT_ID,
        client_secret: process.env.VK_CLIENT_SECRET,
        redirect_uri: process.env.VK_REDIRECT_URI,
        code_verifier: stateData.codeVerifier,
      }
    });

    const { access_token, user_id, email } = tokenResponse.data;

    const userResponse = await axiosInstance.get('https://id.vk.com/method/users.get', {
      params: { access_token, user_ids: user_id, fields: 'photo_200,first_name,last_name' }
    });

    const vkUser = userResponse.data?.response?.[0];
    if (!vkUser) throw new Error('VK user data missing');

    const user = new UnifiedUser(
      'vk', vkUser.id,
      email || `${vkUser.id}@vk.com`,
      `${vkUser.first_name} ${vkUser.last_name}`,
      vkUser.photo_200
    );
    const tokens = generateTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, cookieOptions);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch (error) {
    console.error('VK auth error:', error.response?.data || error.message);
    res.redirect('/?error=vk_auth_failed');
  }
});

// ====== ЯНДЕКС ID ======
app.get('/auth/yandex', authLimiter, (req, res) => {
  const state = generateState();
  const url = new URL('https://oauth.yandex.ru/authorize');
  url.searchParams.set('client_id', process.env.YANDEX_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.YANDEX_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('state', state);
  res.json({ authUrl: url.toString() });
});

app.get('/auth/yandex/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || typeof code !== 'string') return res.redirect('/?error=invalid_code');
    if (!validateState(state)) return res.redirect('/?error=invalid_state');

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: process.env.YANDEX_CLIENT_ID,
      client_secret: process.env.YANDEX_CLIENT_SECRET,
      redirect_uri: process.env.YANDEX_REDIRECT_URI,
    });
    const tokenResponse = await axiosInstance.post('https://oauth.yandex.ru/token', params);
    const { access_token } = tokenResponse.data;

    const userResponse = await axiosInstance.get('https://login.yandex.ru/info', {
      headers: { Authorization: `OAuth ${access_token}` },
      params: { format: 'json' }
    });
    const yaUser = userResponse.data;

    const user = new UnifiedUser(
      'yandex', yaUser.id,
      yaUser.default_email || yaUser.emails?.[0] || `${yaUser.id}@yandex.ru`,
      yaUser.display_name || yaUser.real_name || yaUser.login || 'Yandex User',
      yaUser.default_avatar_id ? `https://avatars.yandex.net/get-yapic/${yaUser.default_avatar_id}/islands-200` : null
    );
    const tokens = generateTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, cookieOptions);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch (error) {
    console.error('Yandex auth error:', error.response?.data || error.message);
    res.redirect('/?error=yandex_auth_failed');
  }
});

// ====== MAIL.RU ======
app.get('/auth/mailru', authLimiter, (req, res) => {
  const state = generateState();
  const url = new URL('https://connect.mail.ru/oauth/authorize');
  url.searchParams.set('client_id', process.env.MAILRU_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.MAILRU_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'userinfo');
  url.searchParams.set('state', state);
  res.json({ authUrl: url.toString() });
});

app.get('/auth/mailru/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || typeof code !== 'string') return res.redirect('/?error=invalid_code');
    if (!validateState(state)) return res.redirect('/?error=invalid_state');

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: process.env.MAILRU_CLIENT_ID,
      client_secret: process.env.MAILRU_CLIENT_SECRET,
      redirect_uri: process.env.MAILRU_REDIRECT_URI,
    });
    const tokenResponse = await axiosInstance.post('https://connect.mail.ru/oauth/token', params);
    const { access_token } = tokenResponse.data;

    const userResponse = await axiosInstance.get('https://www.appsmail.ru/platform/api', {
      params: { method: 'users.getInfo', app_id: process.env.MAILRU_CLIENT_ID, session_key: access_token, secure: 1 }
    });
    const mailUser = userResponse.data[0];
    if (!mailUser) throw new Error('Mail.ru user data missing');

    const user = new UnifiedUser(
      'mailru', mailUser.uid, mailUser.email,
      `${mailUser.first_name} ${mailUser.last_name}`,
      mailUser.pic_50 || mailUser.pic_big
    );
    const tokens = generateTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, cookieOptions);
    res.redirect(`/?token=${tokens.accessToken}`);
  } catch (error) {
    console.error('Mail.ru auth error:', error.response?.data || error.message);
    res.redirect('/?error=mailru_auth_failed');
  }
});

// ====== ОБНОВЛЕНИЕ ТОКЕНА ======
app.post('/auth/refresh', refreshLimiter, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token отсутствует' });
  if (revokedTokens.has(refreshToken)) return res.status(401).json({ error: 'Refresh token отозван' });
  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    if (decoded.type !== 'refresh') throw new Error('Неверный тип токена');
    const user = { id: decoded.userId, email: decoded.email, provider: decoded.provider, name: decoded.name, avatar: decoded.avatar };
    const tokens = generateTokens(user);
    res.cookie('refreshToken', tokens.refreshToken, cookieOptions);
    res.json({ accessToken: tokens.accessToken });
  } catch {
    res.status(403).json({ error: 'Недействительный refresh token' });
  }
});

// ====== ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ ======
app.get('/auth/me', authenticateToken, (req, res) => {
  res.json({ userId: req.user.userId, email: req.user.email, provider: req.user.provider, name: req.user.name || null, avatar: req.user.avatar || null });
});

// ====== ВЫХОД ======
app.post('/auth/logout', authenticateToken, (req, res) => {
  revokedTokens.add(req.token);
  res.clearCookie('refreshToken');
  res.json({ message: 'Выход выполнен успешно' });
});

// ====== ЗАЩИЩЁННЫЙ РОУТ ======
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Это защищённые данные', user: req.user });
});

// ====== ГЛОБАЛЬНЫЙ ОБРАБОТЧИК ОШИБОК ======
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Auth service запущен на http://localhost:${PORT}`);
  console.log(`📡 VK callback: ${process.env.VK_REDIRECT_URI}`);
  console.log(`📡 Yandex callback: ${process.env.YANDEX_REDIRECT_URI}`);
  console.log(`📡 Mail.ru callback: ${process.env.MAILRU_REDIRECT_URI}`);
});
EOF
echo "Done"