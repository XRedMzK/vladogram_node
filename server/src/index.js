const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');
const {
  initDb,
  ensureTestUser,
  ensureChat,
  ensureDirectChat,
  getUserByNickname,
  getUserById,
  updateUserProfile,
  createUserWithTotp,
  createSession,
  createDevice,
  getDeviceById,
  listDevicesByUserId,
  createMessage,
  listMessagesByChat,
  ensureChatMember,
  isChatMember,
  listChatMemberUserIds,
  listChatsByUserId,
  deleteChatMembersByUser,
  deleteMessagesByUser,
  revokeSessionsByUser,
  deleteDevicesByUser,
  ensureUserEpoch,
  bumpUserEpoch,
  createPairing,
  getPairingById,
  updatePairingAccept,
  updatePairingPayload,
  createLoginCode,
  getLoginCodeByHash,
  markLoginCodeUsed,
  getTotpByUserId,
  enableTotp,
  getSessionByRefreshHash,
  updateSessionRefresh,
  revokeSession
} = require('./db');
const {
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TTL_MS,
  buildQrDataUrl,
  createAccessToken,
  createCsrfToken,
  createRefreshToken,
  generateTotpSetup,
  getRefreshExpiry,
  hashToken,
  verifyTotp,
  verifyAccessToken
} = require('./auth');

const app = express();
const port = process.env.PORT || 3000;
const host = process.env.HOST || '0.0.0.0';
const BASE_PATH = process.env.BASE_PATH || '';
const COOKIE_PATH = process.env.COOKIE_PATH || (BASE_PATH ? BASE_PATH : '/');
const SOCKET_PATH = BASE_PATH ? `${BASE_PATH}/socket.io` : '/socket.io';
const apiRouter = express.Router();
const uploadsDir = path.join(__dirname, '../data/uploads');

function createRequestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function formatMeta(meta) {
  if (!meta || typeof meta !== 'object' || Object.keys(meta).length === 0) {
    return '';
  }
  try {
    return ` ${JSON.stringify(meta)}`;
  } catch {
    return '';
  }
}

function logInfo(message, meta) {
  console.log(`[${new Date().toISOString()}] INFO ${message}${formatMeta(meta)}`);
}

function logWarn(message, meta) {
  console.warn(`[${new Date().toISOString()}] WARN ${message}${formatMeta(meta)}`);
}

function logError(message, meta, err) {
  const suffix = formatMeta(meta);
  if (err) {
    console.error(
      `[${new Date().toISOString()}] ERROR ${message}${suffix}\n${err.stack || err}`
    );
    return;
  }
  console.error(`[${new Date().toISOString()}] ERROR ${message}${suffix}`);
}

function ensureUploadsDir() {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
}

let db;
try {
  const initResult = initDb();
  db = initResult.db;
  if (initResult.appliedCount > 0) {
    logInfo('migrations_applied', { count: initResult.appliedCount });
  }
  const user = ensureTestUser(db);
  logInfo('db_ready', { test_user_id: user.id, nickname: user.nickname });
  const chat = ensureChat(db, 1);
  logInfo('default_chat_ready', { chat_id: chat.id });
  ensureUploadsDir();
} catch (err) {
  logError('database_init_failed', {}, err);
  process.exit(1);
}

process.on('unhandledRejection', (reason) => {
  const err = reason instanceof Error ? reason : new Error(String(reason));
  logError('unhandled_rejection', {}, err);
});

process.on('uncaughtException', (err) => {
  logError('uncaught_exception', {}, err);
});

// Basic request logging
app.use((req, res, next) => {
  const start = Date.now();
  const incomingId = req.get('x-request-id');
  req.requestId = incomingId || createRequestId();
  res.set('x-request-id', req.requestId);
  res.on('finish', () => {
    const duration = Date.now() - start;
    logInfo('http_request', {
      id: req.requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      duration_ms: duration,
      user_id: req.user?.id || null
    });
  });
  next();
});

app.use(cookieParser());
app.use(express.json({ limit: '25mb' }));

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited' }
});

const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCK_MS = 5 * 60 * 1000;
const ATTEMPT_WINDOW_MS = 10 * 60 * 1000;
const BASE_DELAY_MS = 300;
const MAX_DELAY_MS = 2000;
const REFRESH_COOKIE = 'refresh_token';
const CSRF_COOKIE = 'csrf_token';
const PAIRING_TTL_MS = 10 * 60 * 1000;
const LOGIN_CODE_TTL_MS = 10 * 60 * 1000;

function getAttemptKey(req, nickname) {
  return `${req.ip || 'unknown'}:${nickname}`;
}

function getAttemptState(key) {
  const state = loginAttempts.get(key);
  if (!state) {
    return null;
  }
  const now = Date.now();
  if (now - state.firstAttemptAt > ATTEMPT_WINDOW_MS) {
    loginAttempts.delete(key);
    return null;
  }
  if (state.lockUntil && state.lockUntil <= now) {
    loginAttempts.delete(key);
    return null;
  }
  return state;
}

function recordFailure(key) {
  const now = Date.now();
  const state = loginAttempts.get(key);
  if (!state || now - state.firstAttemptAt > ATTEMPT_WINDOW_MS) {
    const nextState = { attempts: 1, firstAttemptAt: now, lockUntil: null };
    loginAttempts.set(key, nextState);
    return nextState;
  }

  state.attempts += 1;
  if (state.attempts >= MAX_ATTEMPTS) {
    state.lockUntil = now + LOCK_MS;
  }
  loginAttempts.set(key, state);
  return state;
}

function clearAttempts(key) {
  loginAttempts.delete(key);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isExpired(expiresAt) {
  return new Date(expiresAt).getTime() <= Date.now();
}

function getChatById(dbRef, chatId) {
  return dbRef
    .prepare('SELECT id, epoch, created_at FROM chats WHERE id = ?')
    .get(chatId);
}

function getCsrfFromRequest(req) {
  return req.get('x-csrf-token') || req.body?.csrf_token;
}

function validateCsrf(req) {
  const cookieToken = req.cookies?.[CSRF_COOKIE];
  const requestToken = getCsrfFromRequest(req);
  return Boolean(cookieToken && requestToken && cookieToken === requestToken);
}

function setSessionCookies(res, refreshToken, csrfToken) {
  const isProd =
    process.env.NODE_ENV === 'production' && process.env.ALLOW_INSECURE_HTTP !== '1';
  res.cookie(REFRESH_COOKIE, refreshToken, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProd,
    path: COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  });
  res.cookie(CSRF_COOKIE, csrfToken, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isProd,
    path: COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  });
}

function clearSessionCookies(res) {
  res.clearCookie(REFRESH_COOKIE, { path: COOKIE_PATH });
  res.clearCookie(CSRF_COOKIE, { path: COOKIE_PATH });
}

function chatRoom(chatId) {
  return `chat:${chatId}`;
}

function userRoom(userId) {
  return `user:${userId}`;
}

function parseChatId(value) {
  const id = Number(value);
  if (!Number.isInteger(id) || id <= 0) {
    return null;
  }
  return id;
}

function normalizeBlob(value) {
  if (!value) return value;
  if (Buffer.isBuffer(value)) {
    return value.toString('base64');
  }
  return value;
}

function requireAuth(req, res, next) {
  const authHeader = req.get('authorization');
  if (!authHeader) {
    return res.status(401).json({ error: 'missing_auth' });
  }
  try {
    const payload = verifyAccessToken(authHeader);
    req.user = {
      id: Number(payload.sub),
      nickname: payload.nickname
    };
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Health check
apiRouter.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

apiRouter.post('/auth/register', async (req, res, next) => {
  try {
    const nickname = String(req.body?.nickname || '').trim();
    if (!nickname) {
      return res.status(400).json({ error: 'invalid_nickname' });
    }

    const existing = getUserByNickname(db, nickname);
    if (existing) {
      return res.status(409).json({ error: 'nickname_taken' });
    }

    const totpSetup = generateTotpSetup(nickname);
    const qrDataUrl = await buildQrDataUrl(totpSetup.otpauthUrl);

    const user = createUserWithTotp(db, nickname, totpSetup.secret);
    enableTotp(db, user.id);
    const epoch = ensureUserEpoch(db, user.id);

    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken();
    const refreshHash = hashToken(refreshToken);
    const refreshExpiresAt = getRefreshExpiry();
    const csrfToken = createCsrfToken();

    createSession(db, {
      userId: user.id,
      deviceId: null,
      refreshHash,
      expiresAt: refreshExpiresAt
    });

    setSessionCookies(res, refreshToken, csrfToken);

    const payload = {
      user_id: user.id,
      nickname: user.nickname,
      display_name: user.display_name || user.nickname,
      avatar_url: user.avatar_url || '',
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      csrf_token: csrfToken,
      epoch,
      totp_secret: totpSetup.secret,
      totp_otpauth_url: totpSetup.otpauthUrl,
      totp_qr_data_url: qrDataUrl
    };

    if (process.env.NODE_ENV !== 'production') {
      payload.refresh_token = refreshToken;
      payload.refresh_expires_at = refreshExpiresAt;
    }

    return res.json(payload);
  } catch (err) {
    if (err && err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'nickname_taken' });
    }
    return next(err);
  }
});

apiRouter.post('/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const nickname = String(req.body?.nickname || '').trim();
    const loginCode = String(req.body?.login_code || '').replace(/\s+/g, '').trim();
    if (!nickname || !loginCode) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    const attemptKey = getAttemptKey(req, nickname);
    const state = getAttemptState(attemptKey);
    if (state && state.lockUntil && state.lockUntil > Date.now()) {
      return res.status(429).json({
        error: 'locked',
        retry_after_ms: Math.max(0, state.lockUntil - Date.now())
      });
    }

    if (state && state.attempts > 0) {
      const delay = Math.min(state.attempts * BASE_DELAY_MS, MAX_DELAY_MS);
      await sleep(delay);
    }

    const user = getUserByNickname(db, nickname);
    if (!user) {
      recordFailure(attemptKey);
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    let loginPayload = null;
    let usedLoginCode = false;

    const totp = getTotpByUserId(db, user.id);
    const totpValid = totp?.secret ? verifyTotp(totp.secret, loginCode) : false;
    if (totpValid && totp && !totp.enabled) {
      enableTotp(db, user.id);
    }

    if (!totpValid) {
      const codeHash = hashToken(loginCode);
      const loginRecord = getLoginCodeByHash(db, codeHash);
      if (
        loginRecord &&
        !loginRecord.used &&
        loginRecord.user_id === user.id &&
        !isExpired(loginRecord.expires_at)
      ) {
        markLoginCodeUsed(db, loginRecord.id);
        usedLoginCode = true;
        loginPayload = {
          ciphertext: normalizeBlob(loginRecord.payload_ciphertext),
          nonce: normalizeBlob(loginRecord.payload_nonce),
          meta: loginRecord.payload_meta ? JSON.parse(loginRecord.payload_meta) : null
        };
      }
    }

    if (!totpValid && !usedLoginCode) {
      recordFailure(attemptKey);
      return res.status(401).json({ error: 'invalid_login_code' });
    }

    clearAttempts(attemptKey);
    const accessToken = createAccessToken(user);
    const refreshToken = createRefreshToken();
    const refreshHash = hashToken(refreshToken);
    const refreshExpiresAt = getRefreshExpiry();
    const csrfToken = createCsrfToken();
    const epoch = ensureUserEpoch(db, user.id);

    createSession(db, {
      userId: user.id,
      deviceId: null,
      refreshHash,
      expiresAt: refreshExpiresAt
    });

    setSessionCookies(res, refreshToken, csrfToken);

    const payload = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      csrf_token: csrfToken,
      epoch,
      display_name: user.display_name || user.nickname,
      avatar_url: user.avatar_url || ''
    };

    if (process.env.NODE_ENV !== 'production') {
      payload.refresh_token = refreshToken;
      payload.refresh_expires_at = refreshExpiresAt;
    }

    if (usedLoginCode && loginPayload && (loginPayload.ciphertext || loginPayload.nonce)) {
      payload.login_payload = loginPayload;
    }

    return res.json(payload);
  } catch (err) {
    return next(err);
  }
});

apiRouter.post('/auth/login-code', requireAuth, (req, res) => {
  const code = String(req.body?.code || '').replace(/\s+/g, '').trim();
  if (!code || code.length < 6) {
    return res.status(400).json({ error: 'invalid_login_code' });
  }

  const payloadCiphertext = req.body?.payload_ciphertext || null;
  const payloadNonce = req.body?.payload_nonce || null;
  const payloadMeta = req.body?.payload_meta
    ? JSON.stringify(req.body.payload_meta)
    : null;
  const codeHash = hashToken(code);
  const expiresAt = new Date(Date.now() + LOGIN_CODE_TTL_MS).toISOString();

  db.prepare('UPDATE login_codes SET used = 1 WHERE user_id = ?').run(req.user.id);
  createLoginCode(db, {
    userId: req.user.id,
    codeHash,
    expiresAt,
    payloadCiphertext,
    payloadNonce,
    payloadMeta
  });

  return res.json({ status: 'created', expires_at: expiresAt });
});

apiRouter.post('/auth/refresh', (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE] || req.body?.refresh_token;
  if (!refreshToken) {
    return res.status(401).json({ error: 'missing_refresh' });
  }

  const usingCookie = Boolean(req.cookies?.[REFRESH_COOKIE]);
  if (usingCookie && !validateCsrf(req)) {
    return res.status(403).json({ error: 'csrf_invalid' });
  }

  const refreshHash = hashToken(refreshToken);
  const session = getSessionByRefreshHash(db, refreshHash);
  if (!session || session.revoked) {
    return res.status(401).json({ error: 'invalid_refresh' });
  }
  if (isExpired(session.expires_at)) {
    return res.status(401).json({ error: 'refresh_expired' });
  }

  const user = db
    .prepare('SELECT id, nickname FROM users WHERE id = ?')
    .get(session.user_id);
  if (!user) {
    return res.status(401).json({ error: 'invalid_user' });
  }

  const newRefreshToken = createRefreshToken();
  const newRefreshHash = hashToken(newRefreshToken);
  const refreshExpiresAt = getRefreshExpiry();
  const csrfToken = createCsrfToken();
  const epoch = ensureUserEpoch(db, user.id);

  updateSessionRefresh(db, session.id, newRefreshHash, refreshExpiresAt);

  if (usingCookie) {
    setSessionCookies(res, newRefreshToken, csrfToken);
  }

  const accessToken = createAccessToken(user);
  const payload = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SECONDS
  };

  if (!usingCookie) {
    payload.refresh_token = newRefreshToken;
    payload.refresh_expires_at = refreshExpiresAt;
  } else {
    payload.csrf_token = csrfToken;
    payload.epoch = epoch;
    if (process.env.NODE_ENV !== 'production') {
      payload.refresh_expires_at = refreshExpiresAt;
    }
  }

  return res.json(payload);
});

apiRouter.post('/auth/logout', (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE] || req.body?.refresh_token;
  if (refreshToken) {
    const usingCookie = Boolean(req.cookies?.[REFRESH_COOKIE]);
    if (usingCookie && !validateCsrf(req)) {
      return res.status(403).json({ error: 'csrf_invalid' });
    }
    const refreshHash = hashToken(refreshToken);
    const session = getSessionByRefreshHash(db, refreshHash);
    if (session && !session.revoked) {
      revokeSession(db, session.id);
    }
  }

  clearSessionCookies(res);
  return res.json({ status: 'logged_out' });
});

apiRouter.get('/me', requireAuth, (req, res) => {
  const epoch = ensureUserEpoch(db, req.user.id);
  const user = getUserById(db, req.user.id);
  return res.json({
    user_id: req.user.id,
    nickname: req.user.nickname,
    display_name: user?.display_name || '',
    avatar_url: user?.avatar_url || '',
    epoch
  });
});

apiRouter.post('/me/profile', requireAuth, (req, res) => {
  let displayName =
    typeof req.body?.display_name === 'string'
      ? req.body.display_name.trim()
      : undefined;
  if (displayName === '') {
    displayName = req.user.nickname;
  }
  const avatarUrl =
    typeof req.body?.avatar_url === 'string'
      ? req.body.avatar_url.trim()
      : undefined;
  const updated = updateUserProfile(db, req.user.id, {
    displayName,
    avatarUrl
  });
  if (!updated) {
    return res.status(404).json({ error: 'user_not_found' });
  }
  return res.json({
    display_name: updated.display_name || '',
    avatar_url: updated.avatar_url || ''
  });
});

apiRouter.post('/uploads/image', requireAuth, (req, res) => {
  const dataUrl = String(req.body?.data_url || '').trim();
  if (!dataUrl.startsWith('data:image/')) {
    return res.status(400).json({ error: 'invalid_image' });
  }
  const match = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(dataUrl);
  if (!match) {
    return res.status(400).json({ error: 'invalid_image' });
  }
  ensureUploadsDir();
  const mime = match[1];
  const base64 = match[2];
  let buffer;
  try {
    buffer = Buffer.from(base64, 'base64');
  } catch {
    return res.status(400).json({ error: 'invalid_image' });
  }
  const ext = mime.includes('jpeg') ? 'jpg' : mime.split('/')[1] || 'png';
  const filename = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}.${ext}`;
  const filepath = path.join(uploadsDir, filename);
  try {
    fs.writeFileSync(filepath, buffer);
  } catch {
    return res.status(500).json({ error: 'upload_failed' });
  }
  const url = `${BASE_PATH}/uploads/${filename}`;
  return res.json({ url });
});

apiRouter.get('/chats', requireAuth, (req, res) => {
  const rows = listChatsByUserId(db, req.user.id).map((row) => ({
    chat_id: row.chat_id,
    peer_nickname: row.peer_nickname,
    peer_display_name: row.peer_display_name,
    peer_avatar_url: row.peer_avatar_url,
    last_message_at: row.last_message_at
  }));
  return res.json({ chats: rows });
});

apiRouter.post('/auth/reset', requireAuth, (req, res) => {
  deleteMessagesByUser(db, req.user.id);
  deleteChatMembersByUser(db, req.user.id);
  revokeSessionsByUser(db, req.user.id);
  deleteDevicesByUser(db, req.user.id);
  const epoch = bumpUserEpoch(db, req.user.id);

  clearSessionCookies(res);
  return res.json({ status: 'reset', epoch });
});

apiRouter.post('/devices/register', requireAuth, (req, res) => {
  const name = String(req.body?.name || '').trim() || 'Web device';
  const pubkey = req.body?.pubkey;
  if (!pubkey) {
    return res.status(400).json({ error: 'missing_pubkey' });
  }

  const pubkeyValue = typeof pubkey === 'string' ? pubkey : JSON.stringify(pubkey);
  const info = createDevice(db, {
    userId: req.user.id,
    name,
    pubkey: pubkeyValue
  });

  return res.json({ device_id: info.lastInsertRowid });
});

apiRouter.get('/devices/public', requireAuth, (req, res) => {
  const nickname = String(req.query.nickname || '').trim();
  if (!nickname) {
    return res.status(400).json({ error: 'missing_nickname' });
  }

  const user = getUserByNickname(db, nickname);
  if (!user) {
    return res.status(404).json({ error: 'user_not_found' });
  }

  const devices = listDevicesByUserId(db, user.id).map((device) => ({
    id: device.id,
    name: device.name,
    pubkey: device.pubkey,
    created_at: device.created_at
  }));

  return res.json({ user_id: user.id, nickname: user.nickname, devices });
});

apiRouter.post('/pairings/start', requireAuth, (req, res) => {
  const pubkeyNew = req.body?.pubkey_new;
  if (!pubkeyNew) {
    return res.status(400).json({ error: 'missing_pubkey_new' });
  }

  let deviceIdNew = null;
  if (req.body?.device_id_new) {
    const candidate = Number(req.body.device_id_new);
    if (Number.isInteger(candidate)) {
      const device = getDeviceById(db, candidate);
      if (!device || device.user_id !== req.user.id) {
        return res.status(403).json({ error: 'invalid_device' });
      }
      deviceIdNew = candidate;
    }
  }

  const expiresAt = new Date(Date.now() + PAIRING_TTL_MS).toISOString();
  const pubkeyValue = typeof pubkeyNew === 'string' ? pubkeyNew : JSON.stringify(pubkeyNew);
  const info = createPairing(db, {
    userId: req.user.id,
    deviceIdNew,
    pubkeyNew: pubkeyValue,
    expiresAt,
    state: 'waiting'
  });

  return res.json({ pairing_id: info.lastInsertRowid, expires_at: expiresAt });
});

apiRouter.get('/pairings/:id', requireAuth, (req, res) => {
  const pairingId = Number(req.params.id);
  if (!Number.isInteger(pairingId)) {
    return res.status(400).json({ error: 'invalid_pairing_id' });
  }

  const pairing = getPairingById(db, pairingId);
  if (!pairing || pairing.user_id !== req.user.id) {
    return res.status(404).json({ error: 'pairing_not_found' });
  }
  if (isExpired(pairing.expires_at)) {
    return res.status(410).json({ error: 'pairing_expired' });
  }

  return res.json({
    id: pairing.id,
    state: pairing.state,
    expires_at: pairing.expires_at,
    pubkey_new: pairing.pubkey_new,
    pubkey_old: pairing.pubkey_old,
    payload_ciphertext: normalizeBlob(pairing.payload_ciphertext),
    payload_nonce: normalizeBlob(pairing.payload_nonce),
    payload_meta: pairing.payload_meta,
    verify_code: pairing.verify_code
  });
});

apiRouter.post('/pairings/accept', requireAuth, (req, res) => {
  const pairingId = Number(req.body?.pairingId);
  const pubkeyOld = req.body?.pubkey_old;
  if (!Number.isInteger(pairingId) || !pubkeyOld) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const pairing = getPairingById(db, pairingId);
  if (!pairing || pairing.user_id !== req.user.id) {
    return res.status(404).json({ error: 'pairing_not_found' });
  }
  if (isExpired(pairing.expires_at)) {
    return res.status(410).json({ error: 'pairing_expired' });
  }

  const pubkeyValue = typeof pubkeyOld === 'string' ? pubkeyOld : JSON.stringify(pubkeyOld);
  updatePairingAccept(db, pairingId, pubkeyValue);
  return res.json({ status: 'accepted' });
});

apiRouter.post('/pairings/transfer', requireAuth, (req, res) => {
  const pairingId = Number(req.body?.pairingId);
  const ciphertext = req.body?.ciphertext;
  const nonce = req.body?.nonce;
  if (!Number.isInteger(pairingId) || !ciphertext || !nonce) {
    return res.status(400).json({ error: 'invalid_request' });
  }

  const pairing = getPairingById(db, pairingId);
  if (!pairing || pairing.user_id !== req.user.id) {
    return res.status(404).json({ error: 'pairing_not_found' });
  }
  if (isExpired(pairing.expires_at)) {
    return res.status(410).json({ error: 'pairing_expired' });
  }
  if (pairing.state === 'waiting') {
    return res.status(409).json({ error: 'pairing_not_accepted' });
  }

  const payload = {
    ciphertext,
    nonce,
    metaJson: req.body?.meta ? JSON.stringify(req.body.meta) : null,
    verifyCode: req.body?.verify_code || null
  };
  updatePairingPayload(db, pairingId, payload);
  return res.json({ status: 'transferred' });
});

apiRouter.post('/pairings/qr', requireAuth, async (req, res, next) => {
  try {
    const text = String(req.body?.text || '');
    if (!text) {
      return res.status(400).json({ error: 'missing_text' });
    }
    const qrDataUrl = await buildQrDataUrl(text);
    return res.json({ qr_data_url: qrDataUrl });
  } catch (err) {
    return next(err);
  }
});

apiRouter.get('/chats/:id/messages', requireAuth, (req, res) => {
  const chatId = parseChatId(req.params.id);
  if (!chatId) {
    return res.status(400).json({ error: 'invalid_chat_id' });
  }
  if (!isChatMember(db, chatId, req.user.id)) {
    return res.status(403).json({ error: 'not_chat_member' });
  }
  const limit = Math.min(Number(req.query.limit || 50), 200);
  const rows = listMessagesByChat(db, chatId, limit).map((row) => ({
    id: row.id,
    chatId: row.chat_id,
    sender_user_id: row.sender_user_id,
    sender_nickname: row.sender_nickname,
    sender_display_name: row.sender_display_name,
    sender_avatar_url: row.sender_avatar_url,
    sender_device_id: row.sender_device_id,
    sent_at: row.sent_at,
    ciphertext: normalizeBlob(row.ciphertext),
    nonce: normalizeBlob(row.nonce),
    meta: (() => {
      if (!row.meta_json) return null;
      try {
        return JSON.parse(row.meta_json);
      } catch {
        return null;
      }
    })()
  }));
  return res.json({ chatId, messages: rows.reverse() });
});

apiRouter.post('/chats/direct', requireAuth, (req, res) => {
  const peerNickname = String(req.body?.nickname || '').trim();
  if (!peerNickname) {
    return res.status(400).json({ error: 'missing_nickname' });
  }
  const peer = getUserByNickname(db, peerNickname);
  if (!peer) {
    return res.status(404).json({ error: 'user_not_found' });
  }
  if (peer.id === req.user.id) {
    return res.status(400).json({ error: 'self_chat_not_allowed' });
  }
  const chat = ensureDirectChat(db, req.user.id, peer.id, 1);
  return res.json({
    chat_id: chat.id,
    peer_nickname: peer.nickname,
    peer_display_name: peer.display_name,
    peer_avatar_url: peer.avatar_url
  });
});

apiRouter.post('/chats/:id/join', requireAuth, (req, res) => {
  const chatId = parseChatId(req.params.id);
  if (!chatId) {
    return res.status(400).json({ error: 'invalid_chat_id' });
  }
  const chat = getChatById(db, chatId);
  if (!chat) {
    return res.status(404).json({ error: 'chat_not_found' });
  }
  if (!isChatMember(db, chatId, req.user.id)) {
    return res.status(403).json({ error: 'not_chat_member' });
  }
  return res.json({ status: 'joined', chatId });
});

if (BASE_PATH) {
  app.use(BASE_PATH, apiRouter);
}
app.use(apiRouter);

const server = http.createServer(app);
const io = new Server(server, {
  path: SOCKET_PATH,
  maxHttpBufferSize: 5e6,
  cors: {
    origin: true,
    credentials: true
  }
});

io.use((socket, next) => {
  const token =
    socket.handshake.auth?.token ||
    socket.handshake.headers?.authorization;
  try {
    const payload = verifyAccessToken(token);
    socket.user = {
      id: Number(payload.sub),
      nickname: payload.nickname
    };
    const deviceId = Number(socket.handshake.auth?.deviceId);
    if (Number.isInteger(deviceId) && deviceId > 0) {
      const device = getDeviceById(db, deviceId);
      if (!device || device.user_id !== socket.user.id) {
        logWarn('socket_invalid_device', {
          socket_id: socket.id,
          user_id: socket.user.id,
          device_id: deviceId
        });
        return next(new Error('unauthorized'));
      }
      socket.deviceId = deviceId;
    }
    return next();
  } catch (err) {
    logWarn('socket_auth_failed', {
      socket_id: socket.id,
      ip: socket.handshake.address || null
    });
    return next(new Error('unauthorized'));
  }
});

io.on('connection', (socket) => {
  const user = socket.user;
  logInfo('socket_connected', {
    socket_id: socket.id,
    user_id: user?.id || null,
    device_id: socket.deviceId || null
  });
  socket.join(userRoom(user.id));

  socket.on('chat:join', (payload = {}) => {
    const chatId = parseChatId(payload.chatId);
    if (!chatId) {
      return;
    }
    if (!isChatMember(db, chatId, user.id)) {
      logWarn('chat_join_denied', {
        socket_id: socket.id,
        user_id: user.id,
        chat_id: chatId
      });
      socket.emit('chat:error', { chatId, error: 'not_chat_member' });
      return;
    }
    socket.join(chatRoom(chatId));
    socket.emit('chat:joined', { chatId });
  });

  socket.on('chat:leave', (payload = {}) => {
    const chatId = parseChatId(payload.chatId);
    if (!chatId) {
      return;
    }
    socket.leave(chatRoom(chatId));
    socket.emit('chat:left', { chatId });
  });

  socket.on('typing:start', (payload = {}) => {
    const chatId = parseChatId(payload.chatId);
    if (!chatId) {
      return;
    }
    socket.to(chatRoom(chatId)).emit('typing:start', {
      chatId,
      user_id: user.id,
      nickname: user.nickname
    });
  });

  socket.on('typing:stop', (payload = {}) => {
    const chatId = parseChatId(payload.chatId);
    if (!chatId) {
      return;
    }
    socket.to(chatRoom(chatId)).emit('typing:stop', {
      chatId,
      user_id: user.id,
      nickname: user.nickname
    });
  });

  socket.on('presence:update', (payload = {}) => {
    const chatId = parseChatId(payload.chatId);
    if (!chatId) {
      return;
    }
    socket.to(chatRoom(chatId)).emit('presence:update', {
      chatId,
      user_id: user.id,
      nickname: user.nickname,
      status: payload.status || 'online'
    });
  });

  socket.on('message:send', (payload = {}, ack) => {
    try {
      const chatId = parseChatId(payload.chatId);
      const ciphertext = payload.ciphertext;
      const nonce = payload.nonce;
      if (!chatId || !ciphertext || !nonce) {
        logWarn('message_invalid_payload', {
          socket_id: socket.id,
          user_id: user.id,
          chat_id: payload.chatId || null
        });
        if (typeof ack === 'function') {
          ack({ ok: false, error: 'invalid_payload' });
        }
        return;
      }
      const chat = getChatById(db, chatId);
      if (!chat) {
        logWarn('message_chat_not_found', {
          socket_id: socket.id,
          user_id: user.id,
          chat_id: chatId
        });
        if (typeof ack === 'function') {
          ack({ ok: false, error: 'chat_not_found' });
        }
        return;
      }
      if (!isChatMember(db, chatId, user.id)) {
        logWarn('message_not_chat_member', {
          socket_id: socket.id,
          user_id: user.id,
          chat_id: chatId
        });
        if (typeof ack === 'function') {
          ack({ ok: false, error: 'not_chat_member' });
        }
        return;
      }
      socket.join(chatRoom(chatId));

      const sentAt = new Date().toISOString();
      const metaJson = payload.meta ? JSON.stringify(payload.meta) : null;
      const info = createMessage(db, {
        chatId,
        senderUserId: user.id,
        senderDeviceId: socket.deviceId || null,
        sentAt,
        ciphertext,
        nonce,
        metaJson
      });

      const senderProfile = getUserById(db, user.id);
      const message = {
        id: info.lastInsertRowid,
        chatId,
        sender_user_id: user.id,
        sender_nickname: user.nickname,
        sender_display_name: senderProfile?.display_name || null,
        sender_avatar_url: senderProfile?.avatar_url || null,
        sender_device_id: socket.deviceId || null,
        sent_at: sentAt,
        ciphertext,
        nonce,
        meta: payload.meta || null
      };

      io.to(chatRoom(chatId)).emit('message:new', message);
      const memberIds = listChatMemberUserIds(db, chatId);
      memberIds.forEach((memberId) => {
        if (memberId === user.id) return;
        io.to(userRoom(memberId)).emit('message:new', message);
      });

      if (typeof ack === 'function') {
        ack({ ok: true, id: info.lastInsertRowid, sent_at: sentAt });
      }
    } catch (err) {
      logError(
        'message_send_failed',
        { socket_id: socket.id, user_id: user?.id || null },
        err
      );
      if (typeof ack === 'function') {
        ack({ ok: false, error: 'internal_error' });
      }
    }
  });

  socket.on('disconnect', (reason) => {
    logInfo('socket_disconnected', {
      socket_id: socket.id,
      user_id: user?.id || null,
      reason: reason || null
    });
    socket.rooms.forEach((room) => {
      if (!room.startsWith('chat:')) {
        return;
      }
      const chatId = Number(room.slice(5));
      if (!Number.isInteger(chatId)) {
        return;
      }
      socket.to(room).emit('typing:stop', {
        chatId,
        user_id: user.id,
        nickname: user.nickname
      });
    });
  });
});

// Static client
const clientDir = path.join(__dirname, '../../client');
if (BASE_PATH) {
  app.use(`${BASE_PATH}/uploads`, express.static(uploadsDir));
}
app.use('/uploads', express.static(uploadsDir));
if (BASE_PATH) {
  app.use(BASE_PATH, express.static(clientDir));
}
app.use(express.static(clientDir));

// SPA fallback
const indexPath = path.join(clientDir, 'index.html');
if (BASE_PATH) {
  app.get(`${BASE_PATH}/*`, (req, res, next) => {
    res.sendFile(indexPath, (err) => {
      if (err) next(err);
    });
  });
}
app.get('*', (req, res, next) => {
  res.sendFile(indexPath, (err) => {
    if (err) next(err);
  });
});

// Error handler
app.use((err, req, res, next) => {
  if (err?.type === 'entity.too.large' || err?.status === 413) {
    logWarn('payload_too_large', {
      id: req.requestId || null,
      method: req.method,
      path: req.originalUrl,
      user_id: req.user?.id || null
    });
    return res.status(413).json({ error: 'payload_too_large' });
  }
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    logWarn('invalid_json', {
      id: req.requestId || null,
      method: req.method,
      path: req.originalUrl,
      user_id: req.user?.id || null
    });
    return res.status(400).json({ error: 'invalid_json' });
  }
  logError(
    'http_error',
    {
      id: req.requestId || null,
      method: req.method,
      path: req.originalUrl,
      status: err.status || 500,
      user_id: req.user?.id || null
    },
    err
  );
  return res.status(err.status || 500).json({ error: 'internal_error' });
});

server.listen(port, host, () => {
  logInfo('server_listening', {
    host,
    port,
    base_path: BASE_PATH || '/',
    socket_path: SOCKET_PATH
  });
});
