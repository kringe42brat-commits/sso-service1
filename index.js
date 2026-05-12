const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(cookieParser());
app.use(express.json());
app.use(express.static('public'));

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
  const accessToken = jwt.sign(
    { userId: user.id, email: user.email, provider: user.provider },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId: user.id, type: 'refresh' },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  return { accessToken, refreshToken };
}

// ====== МИДДЛВАР ДЛЯ ПРОВЕРКИ JWT ======
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Токен отсутствует' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Недействительный токен' });
    req.user = user;
    next();
  });
}

// ====== VK ID ======
app.get('/auth/vk', (req, res) => {
  const state = req.query.state || 'random_state';
  const url = new URL('https://id.vk.com/authorize');
  url.searchParams.set('client_id', process.env.VK_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.VK_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'email');
  url.searchParams.set('state', state);
  
  res.json({ authUrl: url.toString() });
});

app.get('/auth/vk/callback', async (req, res) => {
  try {
    const { code } = req.query;
    
    const tokenResponse = await axios.post('https://id.vk.com/oauth2/auth', null, {
      params: {
        grant_type: 'authorization_code',
        code,
        client_id: process.env.VK_CLIENT_ID,
        client_secret: process.env.VK_CLIENT_SECRET,
        redirect_uri: process.env.VK_REDIRECT_URI
      }
    });
    
    const { access_token, user_id, email } = tokenResponse.data;
    
    const userResponse = await axios.get('https://id.vk.com/method/users.get', {
      params: {
        access_token,
        user_ids: user_id,
        fields: 'photo_200,first_name,last_name'
      }
    });
    
    const vkUser = userResponse.data.response[0];
    
    const user = new UnifiedUser(
      'vk',
      vkUser.id,
      email || `${vkUser.id}@vk.com`,
      `${vkUser.first_name} ${vkUser.last_name}`,
      vkUser.photo_200
    );
    
    const tokens = generateTokens(user);
    
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.redirect(`/?token=${tokens.accessToken}`);
    
  } catch (error) {
    console.error('VK auth error:', error.response?.data || error.message);
    res.redirect('/?error=vk_auth_failed');
  }
});

// ====== ЯНДЕКС ID ======
app.get('/auth/yandex', (req, res) => {
  const state = req.query.state || 'random_state';
  const url = new URL('https://oauth.yandex.ru/authorize');
  url.searchParams.set('client_id', process.env.YANDEX_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.YANDEX_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('state', state);
  
  res.json({ authUrl: url.toString() });
});

app.get('/auth/yandex/callback', async (req, res) => {
  try {
    const { code } = req.query;
    
    const params = new URLSearchParams();
params.append('grant_type', 'authorization_code');
params.append('code', code);
params.append('client_id', process.env.YANDEX_CLIENT_ID);
params.append('client_secret', process.env.YANDEX_CLIENT_SECRET);
params.append('redirect_uri', process.env.YANDEX_REDIRECT_URI);

const tokenResponse = await axios.post('https://oauth.yandex.ru/token', params);
    
    const { access_token } = tokenResponse.data;
    
    const userResponse = await axios.get('https://login.yandex.ru/info', {
      headers: {
        Authorization: `OAuth ${access_token}`
      },
      params: {
        format: 'json'
      }
    });
    
    const yaUser = userResponse.data;
    
    const user = new UnifiedUser(
      'yandex',
      yaUser.id,
      yaUser.default_email || yaUser.emails?.[0] || `${yaUser.id}@yandex.ru`,
      yaUser.display_name || yaUser.real_name || yaUser.login || 'Yandex User',
      yaUser.default_avatar_id ? `https://avatars.yandex.net/get-yapic/${yaUser.default_avatar_id}/islands-200` : null
    );
    
    const tokens = generateTokens(user);
    
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.redirect(`/?token=${tokens.accessToken}`);
    
  } catch (error) {
    console.error('Yandex auth error:', error.response?.data || error.message);
    res.redirect('/?error=yandex_auth_failed');
  }
});

// ====== MAIL.RU ======
app.get('/auth/mailru', (req, res) => {
  const state = req.query.state || 'random_state';
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
    const { code } = req.query;
    
        const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', code);
    params.append('client_id', process.env.MAILRU_CLIENT_ID);
    params.append('client_secret', process.env.MAILRU_CLIENT_SECRET);
    params.append('redirect_uri', process.env.MAILRU_REDIRECT_URI);

    const tokenResponse = await axios.post('https://connect.mail.ru/oauth/token', params);
    
    const { access_token } = tokenResponse.data;
    
    const userResponse = await axios.get('https://www.appsmail.ru/platform/api', {
      params: {
        method: 'users.getInfo',
        app_id: process.env.MAILRU_CLIENT_ID,
        session_key: access_token,
        secure: 1
      }
    });
    
    const mailUser = userResponse.data[0];
    
    const user = new UnifiedUser(
      'mailru',
      mailUser.uid,
      mailUser.email,
      `${mailUser.first_name} ${mailUser.last_name}`,
      mailUser.pic_50 || mailUser.pic_big
    );
    
    const tokens = generateTokens(user);
    
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.redirect(`/?token=${tokens.accessToken}`);
    
  } catch (error) {
    console.error('Mail.ru auth error:', error.response?.data || error.message);
    res.redirect('/?error=mailru_auth_failed');
  }
});

// ====== ОБНОВЛЕНИЕ ТОКЕНА ======
app.post('/auth/refresh', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token отсутствует' });
  }
  
  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
    if (decoded.type !== 'refresh') {
      throw new Error('Неверный тип токена');
    }
    
    const user = {
      id: decoded.userId,
      email: decoded.email,
      provider: decoded.provider
    };
    
    const tokens = generateTokens(user);
    
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    res.json({ accessToken: tokens.accessToken });
    
  } catch (error) {
    res.status(403).json({ error: 'Недействительный refresh token' });
  }
});

// ====== ПРОВЕРКА ТЕКУЩЕГО ПОЛЬЗОВАТЕЛЯ ======
app.get('/auth/me', authenticateToken, (req, res) => {
  res.json({
    userId: req.user.userId,
    email: req.user.email,
    provider: req.user.provider
  });
});

// ====== ВЫХОД ======
app.post('/auth/logout', (req, res) => {
  res.clearCookie('refreshToken');
  res.json({ message: 'Выход выполнен успешно' });
});

// ====== ЗАЩИЩЁННЫЙ РОУТ ======
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({
    message: 'Это защищённые данные',
    user: req.user
  });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Auth service запущен на http://localhost:${PORT}`);
  console.log(`📡 VK callback: ${process.env.VK_REDIRECT_URI}`);
  console.log(`📡 Yandex callback: ${process.env.YANDEX_REDIRECT_URI}`);
  console.log(`📡 Mail.ru callback: ${process.env.MAILRU_REDIRECT_URI}`);
});