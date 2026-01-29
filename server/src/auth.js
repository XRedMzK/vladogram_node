const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

const ISSUER = process.env.TOTP_ISSUER || 'Vladogram';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ACCESS_TOKEN_TTL_SECONDS = Number(process.env.ACCESS_TOKEN_TTL_SECONDS || 600);
const REFRESH_TTL_DAYS = Number(process.env.REFRESH_TTL_DAYS || 30);
const REFRESH_TTL_MS = REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000;

if (JWT_SECRET === 'dev-secret-change-me') {
  console.warn('JWT_SECRET is not set; using insecure default for dev only.');
}

authenticator.options = { window: 1 };

function generateTotpSetup(nickname) {
  const secret = authenticator.generateSecret();
  const otpauthUrl = authenticator.keyuri(nickname, ISSUER, secret);
  return { secret, otpauthUrl };
}

async function buildQrDataUrl(otpauthUrl) {
  return QRCode.toDataURL(otpauthUrl);
}

function normalizeToken(token) {
  return String(token || '').replace(/\s+/g, '');
}

function verifyTotp(secret, token) {
  return authenticator.verify({ token: normalizeToken(token), secret });
}

function createAccessToken(user) {
  return jwt.sign(
    { sub: String(user.id), nickname: user.nickname },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL_SECONDS }
  );
}

function verifyAccessToken(token) {
  if (!token) {
    throw new Error('missing token');
  }
  const clean = String(token).startsWith('Bearer ')
    ? String(token).slice(7)
    : String(token);
  return jwt.verify(clean, JWT_SECRET);
}

function createRefreshToken() {
  return crypto
    .randomBytes(32)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function createCsrfToken() {
  return createRefreshToken();
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function getRefreshExpiry() {
  return new Date(Date.now() + REFRESH_TTL_MS).toISOString();
}

module.exports = {
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TTL_MS,
  buildQrDataUrl,
  createAccessToken,
  createCsrfToken,
  createRefreshToken,
  generateTotpSetup,
  getRefreshExpiry,
  hashToken,
  normalizeToken,
  verifyTotp,
  verifyAccessToken
};
