const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const dataDir = path.join(__dirname, '../data');
const dbPath = path.join(dataDir, 'vladogram.db');
const migrationsDir = path.join(__dirname, '../migrations');

function ensureDirs() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
}

function getMigrationFiles() {
  if (!fs.existsSync(migrationsDir)) {
    return [];
  }

  return fs
    .readdirSync(migrationsDir)
    .filter((file) => file.endsWith('.sql'))
    .sort();
}

function runMigrations(db) {
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );`
  );

  const appliedVersions = new Set(
    db.prepare('SELECT version FROM schema_migrations').all().map((row) => row.version)
  );

  const insertVersion = db.prepare('INSERT INTO schema_migrations (version) VALUES (?)');

  const files = getMigrationFiles();
  const applyMigration = db.transaction((version, sql) => {
    db.exec(sql);
    insertVersion.run(version);
  });

  let appliedCount = 0;
  for (const file of files) {
    const match = /^([0-9]+)_/.exec(file);
    if (!match) {
      throw new Error(`Invalid migration filename: ${file}`);
    }
    const version = Number(match[1]);
    if (appliedVersions.has(version)) {
      continue;
    }

    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    applyMigration(version, sql);
    appliedCount += 1;
  }

  return appliedCount;
}

function initDb() {
  ensureDirs();
  const db = new Database(dbPath);
  const appliedCount = runMigrations(db);
  return { db, appliedCount };
}

function ensureTestUser(db) {
  const nickname = 'test';
  const existing = db
    .prepare('SELECT id, nickname, created_at FROM users WHERE nickname = ?')
    .get(nickname);

  if (existing) {
    return existing;
  }

  const info = db
    .prepare('INSERT INTO users (nickname) VALUES (?)')
    .run(nickname);

  return db
    .prepare('SELECT id, nickname, created_at FROM users WHERE id = ?')
    .get(info.lastInsertRowid);
}

function ensureChat(db, chatId = 1) {
  const existing = db.prepare('SELECT id, epoch FROM chats WHERE id = ?').get(chatId);
  if (existing) {
    return existing;
  }

  db.prepare('INSERT INTO chats (id, epoch) VALUES (?, 1)').run(chatId);
  return { id: chatId, epoch: 1 };
}

function getUserByNickname(db, nickname) {
  return db
    .prepare('SELECT id, nickname, created_at FROM users WHERE nickname = ?')
    .get(nickname);
}

function createUserWithTotp(db, nickname, secret) {
  const insertUser = db.prepare('INSERT INTO users (nickname) VALUES (?)');
  const insertTotp = db.prepare(
    'INSERT INTO totp (user_id, secret, enabled) VALUES (?, ?, 0)'
  );
  const selectUser = db.prepare(
    'SELECT id, nickname, created_at FROM users WHERE id = ?'
  );

  const createTx = db.transaction((nicknameValue, secretValue) => {
    const info = insertUser.run(nicknameValue);
    insertTotp.run(info.lastInsertRowid, secretValue);
    return selectUser.get(info.lastInsertRowid);
  });

  return createTx(nickname, secret);
}

function getTotpByUserId(db, userId) {
  return db
    .prepare('SELECT user_id, secret, enabled FROM totp WHERE user_id = ?')
    .get(userId);
}

function enableTotp(db, userId) {
  return db.prepare('UPDATE totp SET enabled = 1 WHERE user_id = ?').run(userId);
}

function createSession(db, { userId, deviceId, refreshHash, expiresAt }) {
  return db
    .prepare(
      'INSERT INTO sessions (user_id, device_id, refresh_hash, expires_at, revoked) VALUES (?, ?, ?, ?, 0)'
    )
    .run(userId, deviceId, refreshHash, expiresAt);
}

function createDevice(db, { userId, name, pubkey }) {
  return db
    .prepare(
      'INSERT INTO devices (user_id, name, pubkey, created_at) VALUES (?, ?, ?, datetime(\'now\'))'
    )
    .run(userId, name, pubkey);
}

function getDeviceById(db, deviceId) {
  return db
    .prepare('SELECT id, user_id, name, pubkey, created_at FROM devices WHERE id = ?')
    .get(deviceId);
}

function listDevicesByUserId(db, userId) {
  return db
    .prepare(
      'SELECT id, name, pubkey, created_at FROM devices WHERE user_id = ? AND pubkey IS NOT NULL ORDER BY created_at DESC'
    )
    .all(userId);
}

function createMessage(db, {
  chatId,
  senderUserId,
  senderDeviceId,
  sentAt,
  ciphertext,
  nonce,
  metaJson
}) {
  return db
    .prepare(
      `INSERT INTO messages
        (chat_id, sender_user_id, sender_device_id, sent_at, ciphertext, nonce, meta_json)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .run(chatId, senderUserId, senderDeviceId, sentAt, ciphertext, nonce, metaJson);
}

function ensureChatMember(db, chatId, userId) {
  return db
    .prepare('INSERT OR IGNORE INTO chat_members (chat_id, user_id) VALUES (?, ?)')
    .run(chatId, userId);
}

function isChatMember(db, chatId, userId) {
  const row = db
    .prepare('SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?')
    .get(chatId, userId);
  return Boolean(row);
}

function listMessagesByChat(db, chatId, limit = 50) {
  return db
    .prepare(
      `SELECT id, chat_id, sender_user_id, sender_device_id, sent_at, ciphertext, nonce, meta_json
       FROM messages
       WHERE chat_id = ?
       ORDER BY sent_at DESC
       LIMIT ?`
    )
    .all(chatId, limit);
}

function deleteChatMembersByUser(db, userId) {
  return db.prepare('DELETE FROM chat_members WHERE user_id = ?').run(userId);
}

function deleteMessagesByUser(db, userId) {
  return db.prepare('DELETE FROM messages WHERE sender_user_id = ?').run(userId);
}

function revokeSessionsByUser(db, userId) {
  return db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?').run(userId);
}

function deleteDevicesByUser(db, userId) {
  return db.prepare('DELETE FROM devices WHERE user_id = ?').run(userId);
}

function ensureUserEpoch(db, userId) {
  const existing = db
    .prepare('SELECT epoch FROM user_epochs WHERE user_id = ?')
    .get(userId);
  if (existing) {
    return existing.epoch;
  }
  db.prepare('INSERT INTO user_epochs (user_id, epoch) VALUES (?, 1)').run(userId);
  return 1;
}

function bumpUserEpoch(db, userId) {
  const current = ensureUserEpoch(db, userId);
  const next = current + 1;
  db.prepare(
    'UPDATE user_epochs SET epoch = ?, updated_at = datetime(\'now\') WHERE user_id = ?'
  ).run(next, userId);
  return next;
}

function createPairing(db, {
  userId,
  deviceIdNew,
  pubkeyNew,
  expiresAt,
  state
}) {
  return db
    .prepare(
      `INSERT INTO pairings
        (user_id, device_id_new, pubkey_new, expires_at, state)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(userId, deviceIdNew, pubkeyNew, expiresAt, state);
}

function getPairingById(db, pairingId) {
  return db
    .prepare(
      `SELECT id, user_id, device_id_new, pubkey_new, pubkey_old,
              expires_at, state, payload_ciphertext, payload_nonce,
              payload_meta, verify_code
       FROM pairings
       WHERE id = ?`
    )
    .get(pairingId);
}

function updatePairingAccept(db, pairingId, pubkeyOld) {
  return db
    .prepare(
      `UPDATE pairings
       SET pubkey_old = ?, state = 'accepted'
       WHERE id = ?`
    )
    .run(pubkeyOld, pairingId);
}

function updatePairingPayload(db, pairingId, payload) {
  return db
    .prepare(
      `UPDATE pairings
       SET payload_ciphertext = ?,
           payload_nonce = ?,
           payload_meta = ?,
           verify_code = ?,
           state = 'completed'
       WHERE id = ?`
    )
    .run(
      payload.ciphertext,
      payload.nonce,
      payload.metaJson,
      payload.verifyCode,
      pairingId
    );
}

function getSessionByRefreshHash(db, refreshHash) {
  return db
    .prepare(
      `SELECT id, user_id, device_id, refresh_hash, expires_at, revoked
       FROM sessions
       WHERE refresh_hash = ?`
    )
    .get(refreshHash);
}

function updateSessionRefresh(db, sessionId, refreshHash, expiresAt) {
  return db
    .prepare(
      'UPDATE sessions SET refresh_hash = ?, expires_at = ?, revoked = 0 WHERE id = ?'
    )
    .run(refreshHash, expiresAt, sessionId);
}

function revokeSession(db, sessionId) {
  return db.prepare('UPDATE sessions SET revoked = 1 WHERE id = ?').run(sessionId);
}

module.exports = {
  initDb,
  ensureTestUser,
  ensureChat,
  getUserByNickname,
  createUserWithTotp,
  getTotpByUserId,
  enableTotp,
  createSession,
  createDevice,
  getDeviceById,
  listDevicesByUserId,
  createMessage,
  ensureChatMember,
  isChatMember,
  listMessagesByChat,
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
  getSessionByRefreshHash,
  updateSessionRefresh,
  revokeSession
};
