const appShell = document.getElementById('app-shell');
const authScreen = document.getElementById('auth-screen');
const cryptoWarning = document.getElementById('crypto-warning');

const BASE_PATH = '/vladogram';
const api = (p) => `${BASE_PATH}${p.startsWith('/') ? '' : '/'}${p}`;

const menuBtn = document.getElementById('menu-btn');
const menuModal = document.getElementById('menu-modal');
const menuAvatar = document.getElementById('menu-avatar');
const menuNickname = document.getElementById('menu-nickname');
const openSettingsBtn = document.getElementById('open-settings-btn');
const settingsModal = document.getElementById('settings-modal');
const menuCloseEls = Array.from(document.querySelectorAll('[data-close="menu"]'));
const settingsCloseEls = Array.from(document.querySelectorAll('[data-close="settings"]'));

const socketStatus = document.getElementById('socket-status');
const chatSearchInput = document.getElementById('chat-search');
const chatList = document.getElementById('chat-list');
const chatCreateForm = document.getElementById('chat-create-form');
const newChatPeerInput = document.getElementById('new-chat-peer');

const chatTitle = document.getElementById('chat-title');
const chatConnection = document.getElementById('chat-connection');
const chatPeer = document.getElementById('chat-peer');
const chatBack = document.getElementById('chat-back');
const chatEmpty = document.getElementById('chat-empty');
const typingStatus = document.getElementById('typing-status');
const messagesEl = document.getElementById('messages');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const attachBtn = document.getElementById('attach-btn');
const attachMenu = document.getElementById('attach-menu');
const attachImageInput = document.getElementById('attach-image');
const attachDocInput = document.getElementById('attach-doc');
const attachStatus = document.getElementById('attach-status');

const registerForm = document.getElementById('register-form');
const verifyForm = document.getElementById('verify-form');
const loginForm = document.getElementById('login-form');
const refreshForm = document.getElementById('refresh-form');

const registerNickname = document.getElementById('register-nickname');
const verifyNickname = document.getElementById('verify-nickname');
const verifyCode = document.getElementById('verify-code');
const loginNickname = document.getElementById('login-nickname');
const loginCode = document.getElementById('login-code');
const loginOneTime = document.getElementById('login-one-time');

const registerStatus = document.getElementById('register-status');
const verifyStatus = document.getElementById('verify-status');
const loginStatus = document.getElementById('login-status');
const loginOutput = document.getElementById('login-output');
const refreshStatus = document.getElementById('refresh-status');
const refreshOutput = document.getElementById('refresh-output');

const qrBlock = document.getElementById('register-qr');
const qrImage = document.getElementById('qr-image');
const otpauthUrl = document.getElementById('otpauth-url');

const pairingStartBtn = document.getElementById('pairing-start-btn');
const pairingAcceptBtn = document.getElementById('pairing-accept-btn');
const pairingConfirmBtn = document.getElementById('pairing-confirm-btn');
const pairingInput = document.getElementById('pairing-input');
const pairingQrBlock = document.getElementById('pairing-qr-block');
const pairingQrImage = document.getElementById('pairing-qr-image');
const pairingQrText = document.getElementById('pairing-qr-text');
const pairingCodeNew = document.getElementById('pairing-code-new');
const pairingCodeOld = document.getElementById('pairing-code-old');
const pairingTransferStatus = document.getElementById('pairing-transfer-status');
const changePointBtn = document.getElementById('change-point-btn');
const logoutBtn = document.getElementById('logout-btn');
const settingsStatus = document.getElementById('settings-status');
const loginCodeBtn = document.getElementById('login-code-btn');
const loginCodeValue = document.getElementById('login-code-value');
const loginCodeStatus = document.getElementById('login-code-status');

const state = {
  accessToken: '',
  user: null,
  deviceId: null,
  csrfToken: '',
  epoch: 1,
  chats: [],
  currentChatId: null,
  searchTerm: ''
};

const DB_NAME = 'vladogram';
const DB_VERSION = 1;
let dbPromise = null;
const textEncoder = new TextEncoder();

function openDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('deviceIdentity')) {
        db.createObjectStore('deviceIdentity', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('trustedContacts')) {
        db.createObjectStore('trustedContacts', { keyPath: 'contactId' });
      }
      if (!db.objectStoreNames.contains('chatKeys')) {
        db.createObjectStore('chatKeys', { keyPath: 'chatId' });
      }
      if (!db.objectStoreNames.contains('appState')) {
        db.createObjectStore('appState', { keyPath: 'key' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return dbPromise;
}

async function dbGet(storeName, key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const request = store.get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbPut(storeName, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    const request = store.put(value);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function dbGetAll(storeName) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const request = store.getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

async function getAppValue(key, defaultValue) {
  const record = await dbGet('appState', key);
  if (record && Object.prototype.hasOwnProperty.call(record, 'value')) {
    return record.value;
  }
  await dbPut('appState', { key, value: defaultValue });
  return defaultValue;
}

async function setAppValue(key, value) {
  await dbPut('appState', { key, value });
}

async function setCsrfToken(token) {
  state.csrfToken = token || '';
  await setAppValue('csrfToken', state.csrfToken);
}

const messagesByChat = new Map();
const typingUsers = new Map();
const lastSeenByChat = new Map();
let socket = null;
let typingTimer = null;
let isTyping = false;
const pairingState = {
  newDevice: null,
  oldDevice: null,
  pollTimer: null
};

function setStatus(el, message, type) {
  if (!el) return;
  el.textContent = message;
  if (type) {
    el.dataset.type = type;
  } else {
    delete el.dataset.type;
  }
}

function showError(el, message) {
  setStatus(el, message, 'error');
}

function showSuccess(el, message) {
  setStatus(el, message, 'success');
}

function setAuthVisible(show) {
  if (authScreen) {
    authScreen.classList.toggle('is-visible', show);
  }
  if (appShell) {
    appShell.classList.toggle('is-blurred', show);
  }
  if (show) {
    closeModal(menuModal);
    closeModal(settingsModal);
  }
}

function openModal(modal) {
  if (modal) {
    modal.classList.add('is-open');
  }
}

function closeModal(modal) {
  if (modal) {
    modal.classList.remove('is-open');
  }
}

function cryptoAvailable() {
  return Boolean(window.isSecureContext && window.crypto?.subtle);
}

function ensureCryptoAvailable(target) {
  if (cryptoAvailable()) return true;
  const message = 'Для Web Crypto нужен безопасный контекст (HTTPS или localhost).';
  if (target) {
    showError(target, message);
  } else if (cryptoWarning) {
    showError(cryptoWarning, message);
  }
  return false;
}

function formatTime(value) {
  if (!value) return '';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatLastSeen(value) {
  if (!value) return 'Был(а) в сети: -';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return 'Был(а) в сети: -';
  return `Был(а) в сети: ${formatTime(date)}`;
}

function parseJwt(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = decodeURIComponent(
      atob(payload)
        .split('')
        .map((char) => `%${`00${char.charCodeAt(0).toString(16)}`.slice(-2)}`)
        .join('')
    );
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function normalizeCode(value) {
  return String(value || '').replace(/\s+/g, '').trim();
}

function toBase64(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

function bufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function randomBase64(bytes) {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  let binary = '';
  buffer.forEach((value) => {
    binary += String.fromCharCode(value);
  });
  return btoa(binary);
}

async function ensureEpoch() {
  const epoch = await getAppValue('epoch', 1);
  state.epoch = Number(epoch) || 1;
  return state.epoch;
}

async function importPublicKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
}

async function importPrivateKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
}

async function importAesKey(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM' }, true, [
    'encrypt',
    'decrypt'
  ]);
}

async function ensureDeviceIdentity() {
  if (!ensureCryptoAvailable(cryptoWarning)) {
    return {
      id: 'primary',
      publicJwk: null,
      privateJwk: null,
      deviceId: null,
      userId: null
    };
  }
  const existing = await dbGet('deviceIdentity', 'primary');
  if (existing?.publicJwk && existing?.privateJwk) {
    return existing;
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const record = {
    id: 'primary',
    publicJwk,
    privateJwk,
    deviceId: null,
    userId: null
  };
  await dbPut('deviceIdentity', record);
  return record;
}

async function saveDeviceId(deviceId, userId) {
  const identity = await ensureDeviceIdentity();
  const updated = { ...identity, deviceId, userId };
  await dbPut('deviceIdentity', updated);
  state.deviceId = deviceId;
}

async function getDeviceId() {
  const identity = await ensureDeviceIdentity();
  state.deviceId = identity.deviceId || null;
  return state.deviceId;
}

async function fingerprintJwk(jwk) {
  const data = textEncoder.encode(JSON.stringify(jwk));
  const hash = await crypto.subtle.digest('SHA-256', data);
  return bufferToBase64(hash);
}

async function storeTrustedContact(nickname, deviceId, publicJwk) {
  const fingerprint = await fingerprintJwk(publicJwk);
  const contactId = `${nickname}:${deviceId}`;
  await dbPut('trustedContacts', {
    contactId,
    nickname,
    deviceId,
    publicJwk,
    fingerprint,
    addedAt: new Date().toISOString()
  });
  return fingerprint;
}

async function getChatKeyRecord(chatId) {
  return dbGet('chatKeys', String(chatId));
}

async function saveChatKeyRecord(record) {
  await dbPut('chatKeys', record);
}

function buildNonce(counter) {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce.subarray(0, 4));
  let value = BigInt(counter);
  for (let i = 0; i < 8; i += 1) {
    nonce[11 - i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return nonce;
}

async function deriveChatKey({ privateJwk, peerPublicJwk, chatId, epoch }) {
  const privateKey = await importPrivateKey(privateJwk);
  const publicKey = await importPublicKey(peerPublicJwk);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, [
    'deriveKey'
  ]);
  const salt = textEncoder.encode(`vladogram:${chatId}:${epoch}`);
  const info = textEncoder.encode('chat-key');
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function derivePairingKey({ privateJwk, peerPublicJwk, pairingId }) {
  const privateKey = await importPrivateKey(privateJwk);
  const publicKey = await importPublicKey(peerPublicJwk);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, [
    'deriveKey'
  ]);
  const salt = textEncoder.encode(`pairing:${pairingId}`);
  const info = textEncoder.encode('pairing-channel');
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function deriveLoginCodeKey(code) {
  const normalized = normalizeCode(code);
  const material = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(normalized),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const salt = textEncoder.encode('vladogram-login-code');
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

function generateLoginCode() {
  const value = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(value).padStart(6, '0');
}

async function encryptLoginPayload(code, payload) {
  const key = await deriveLoginCodeKey(code);
  const nonce = randomBase64(12);
  const json = JSON.stringify(payload);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: base64ToBytes(nonce) },
    key,
    textEncoder.encode(json)
  );
  return {
    ciphertext: bufferToBase64(cipherBuffer),
    nonce,
    meta: { version: payload?.version || 1, exported_at: payload?.exported_at }
  };
}

async function decryptLoginPayload(code, payload) {
  if (!payload?.ciphertext || !payload?.nonce) {
    return null;
  }
  try {
    const key = await deriveLoginCodeKey(code);
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(payload.nonce) },
      key,
      base64ToBytes(payload.ciphertext)
    );
    const json = new TextDecoder().decode(plainBuffer);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

async function computePairingCode(pairingKey, pairingId) {
  const raw = await crypto.subtle.exportKey('raw', pairingKey);
  const pairingBytes = textEncoder.encode(String(pairingId));
  const combined = new Uint8Array(raw.byteLength + pairingBytes.length);
  combined.set(new Uint8Array(raw), 0);
  combined.set(pairingBytes, raw.byteLength);
  const hash = await crypto.subtle.digest('SHA-256', combined);
  const view = new DataView(hash);
  const code = view.getUint32(0, false) % 1000000;
  return String(code).padStart(6, '0');
}

async function ensureChatKey(chatId, peerNickname) {
  const existing = await getChatKeyRecord(chatId);
  if (existing?.keyJwk) {
    if (peerNickname && !existing.peerNickname) {
      existing.peerNickname = peerNickname;
      await saveChatKeyRecord(existing);
    }
    return existing;
  }

  if (!peerNickname) {
    return null;
  }

  const identity = await ensureDeviceIdentity();
  if (!identity.privateJwk || !identity.publicJwk) {
    return null;
  }

  const peerData = await fetchPeerDeviceKey(peerNickname);
  if (!peerData) {
    return null;
  }

  const chatKey = await deriveChatKey({
    privateJwk: identity.privateJwk,
    peerPublicJwk: peerData.publicJwk,
    chatId,
    epoch: state.epoch
  });

  const keyJwk = await crypto.subtle.exportKey('jwk', chatKey);
  const record = {
    chatId: String(chatId),
    keyJwk,
    counter: 0,
    epoch: state.epoch,
    peerNickname,
    peerDeviceId: peerData.deviceId
  };
  await saveChatKeyRecord(record);
  const chat = ensureChat(chatId, peerNickname);
  chat.peerDeviceId = peerData.deviceId;
  return record;
}

async function encryptForChat(chatId, plaintext) {
  if (!cryptoAvailable()) {
    return null;
  }
  const record = await getChatKeyRecord(chatId);
  if (!record?.keyJwk) {
    return null;
  }
  if (!state.deviceId) {
    return null;
  }
  const key = await importAesKey(record.keyJwk);
  const nextCounter = Number(record.counter || 0) + 1;
  const nonce = buildNonce(nextCounter);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    textEncoder.encode(plaintext)
  );

  record.counter = nextCounter;
  await saveChatKeyRecord(record);

  return {
    ciphertext: bufferToBase64(cipherBuffer),
    nonce: bufferToBase64(nonce),
    meta: {
      senderDeviceId: state.deviceId,
      epoch: record.epoch || state.epoch,
      counter: nextCounter
    }
  };
}

async function decryptForChat(chatId, ciphertext, nonce) {
  if (!cryptoAvailable()) {
    return null;
  }
  const record = await getChatKeyRecord(chatId);
  if (!record?.keyJwk || !ciphertext || !nonce) {
    return null;
  }
  const key = await importAesKey(record.keyJwk);
  try {
    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(nonce) },
      key,
      base64ToBytes(ciphertext)
    );
    return new TextDecoder().decode(plainBuffer);
  } catch {
    return null;
  }
}

async function exportKeyMaterial() {
  const epoch = await getAppValue('epoch', 1);
  const chatKeys = await dbGetAll('chatKeys');
  const trustedContacts = await dbGetAll('trustedContacts');
  return {
    version: 1,
    epoch,
    chatKeys,
    trustedContacts,
    exported_at: new Date().toISOString()
  };
}

async function importKeyMaterial(payload) {
  if (!payload) return false;
  if (payload.epoch) {
    await setAppValue('epoch', payload.epoch);
    state.epoch = Number(payload.epoch) || state.epoch;
  }
  if (Array.isArray(payload.chatKeys)) {
    for (const record of payload.chatKeys) {
      if (record?.chatId && record?.keyJwk) {
        await dbPut('chatKeys', record);
        ensureChat(record.chatId, record.peerNickname || null);
      }
    }
  }
  if (Array.isArray(payload.trustedContacts)) {
    for (const record of payload.trustedContacts) {
      if (record?.contactId && record?.publicJwk) {
        await dbPut('trustedContacts', record);
      }
    }
  }
  return true;
}

function setAccessToken(token) {
  state.accessToken = token;
  state.user = parseJwt(token);
  updateUserUI();
}

function clearAuth() {
  state.accessToken = '';
  state.user = null;
  state.deviceId = null;
  state.csrfToken = '';
  setAppValue('csrfToken', '').catch(() => {});
  updateUserUI();
  if (loginCodeValue) {
    loginCodeValue.textContent = '';
  }
  setStatus(loginCodeStatus, '');
  setAuthVisible(true);
  state.currentChatId = null;
  setChatActive(false);
  updateChatHeader(null);
  if (socket) {
    socket.disconnect();
    socket = null;
  }
  updateSocketStatus('Отключено');
  stopPairingPoll();
}

function updateUserUI() {
  const label = state.user?.nickname || 'Гость';
  if (menuNickname) {
    menuNickname.textContent = label;
  }
  if (menuAvatar) {
    menuAvatar.textContent = label ? label.charAt(0).toUpperCase() : '?';
  }
}

function getChatDisplayName(chat) {
  if (!chat) return 'Чат';
  return chat.peerNickname || 'Чат';
}

function ensureChat(chatId, peerNickname = null) {
  const id = String(chatId);
  const existing = state.chats.find((chat) => chat.id === id);
  if (existing) {
    if (peerNickname && !existing.peerNickname) {
      existing.peerNickname = peerNickname;
      existing.title = peerNickname;
    }
    return existing;
  }
  const record = {
    id,
    title: peerNickname || 'Чат',
    peerNickname: peerNickname || null,
    peerDeviceId: null,
    lastMessageAt: null,
    lastMessageText: ''
  };
  state.chats.push(record);
  return record;
}

function updateChatHeader(chatId) {
  const chat = state.chats.find((item) => item.id === String(chatId));
  const title = chat ? getChatDisplayName(chat) : 'Чат не выбран';
  if (chatTitle) {
    chatTitle.textContent = title;
  }
  if (chatPeer) {
    const lastSeen = lastSeenByChat.get(String(chatId));
    chatPeer.textContent = formatLastSeen(lastSeen);
  }
}

function setChatActive(active) {
  if (chatEmpty) {
    chatEmpty.classList.toggle('is-visible', !active);
  }
  if (messageForm) {
    messageForm.classList.toggle('is-disabled', !active);
  }
  if (messageInput) {
    messageInput.disabled = !active;
  }
  if (attachBtn) {
    attachBtn.disabled = !active;
  }
  if (!active) {
    updateAttachmentStatus(null);
    attachMenu?.classList.add('is-hidden');
  }
}

function updateAttachmentStatus(file) {
  if (!attachStatus) return;
  if (!file) {
    setStatus(attachStatus, '');
    return;
  }
  setStatus(attachStatus, `Файл готов: ${file.name}`);
}

function renderChatList() {
  if (!chatList) return;
  const search = (chatSearchInput?.value || state.searchTerm || '')
    .toLowerCase()
    .trim();
  const sorted = [...state.chats].sort((a, b) => {
    const timeA = a.lastMessageAt ? Date.parse(a.lastMessageAt) : 0;
    const timeB = b.lastMessageAt ? Date.parse(b.lastMessageAt) : 0;
    return timeB - timeA;
  });

  chatList.innerHTML = '';
  const filtered = sorted.filter((chat) => {
    const name = getChatDisplayName(chat).toLowerCase();
    return !search || name.includes(search);
  });

  if (filtered.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'chat-meta';
    empty.textContent = search ? 'Чаты не найдены.' : 'Пока нет чатов.';
    chatList.appendChild(empty);
    return;
  }

  filtered.forEach((chat) => {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'chat-item';
    if (String(chat.id) === String(state.currentChatId)) {
      item.classList.add('is-active');
    }

    const avatar = document.createElement('div');
    avatar.className = 'chat-avatar';
    const label = getChatDisplayName(chat);
    avatar.textContent = label ? label.charAt(0).toUpperCase() : '#';

    const info = document.createElement('div');
    info.className = 'chat-info';

    const name = document.createElement('div');
    name.className = 'chat-name';
    name.textContent = label;

    const preview = document.createElement('div');
    preview.className = 'chat-preview';
    preview.textContent = chat.lastMessageText || 'Сообщений пока нет';

    const meta = document.createElement('div');
    meta.className = 'chat-meta';
    meta.textContent = chat.lastMessageAt ? formatTime(chat.lastMessageAt) : 'Новый чат';

    info.append(name, preview, meta);

    const time = document.createElement('div');
    time.className = 'chat-meta';
    time.textContent = chat.lastMessageAt ? formatTime(chat.lastMessageAt) : '';

    item.append(avatar, info, time);
    item.addEventListener('click', () => {
      navigateToChat(chat);
    });
    chatList.appendChild(item);
  });
}

async function loadChatsFromStorage() {
  const records = await dbGetAll('chatKeys');
  records.forEach((record) => {
    if (record?.chatId) {
      ensureChat(record.chatId, record.peerNickname || null);
    }
  });
  renderChatList();
}

async function loadChatsFromServer() {
  if (!state.accessToken) return;
  const { ok, data } = await getJson('/chats');
  if (!ok || !data?.chats) {
    return;
  }
  data.chats.forEach((row) => {
    const chat = ensureChat(row.chat_id, row.peer_nickname || null);
    if (row.last_message_at) {
      const currentTime = chat.lastMessageAt ? Date.parse(chat.lastMessageAt) : 0;
      const incomingTime = Date.parse(row.last_message_at);
      if (!currentTime || (incomingTime && incomingTime > currentTime)) {
        chat.lastMessageAt = row.last_message_at;
      }
    }
  });
  renderChatList();
}

function parseRoute() {
  const hash = window.location.hash || '#/chats';
  const parts = hash.replace(/^#\//, '').split('/');
  const name = parts[0] || 'chats';
  if (name === 'chat') {
    return { name: 'chat', peer: parts[1] };
  }
  if (['auth', 'chats'].includes(name)) {
    return { name };
  }
  return { name: 'chats' };
}

function navigateTo(route) {
  window.location.hash = route;
}

function navigateToChat(chat) {
  if (!chat) return;
  const label = chat.peerNickname || chat.id || '';
  if (!label) return;
  navigateTo(`#/chat/${encodeURIComponent(label)}`);
}

function findChatByPeer(peerNickname) {
  if (!peerNickname) return null;
  const needle = peerNickname.toLowerCase();
  return (
    state.chats.find(
      (chat) => chat.peerNickname && chat.peerNickname.toLowerCase() === needle
    ) || null
  );
}

async function openDirectChat(peerNickname, { navigate = false } = {}) {
  const nickname = String(peerNickname || '').trim();
  if (!nickname) return null;
  if (!state.accessToken) {
    showError(socketStatus, 'Нужен вход, чтобы открыть чат.');
    return null;
  }

  const existing = findChatByPeer(nickname);
  if (existing) {
    if (navigate !== false) {
      navigateToChat(existing);
    }
    await joinChat(existing.id, { silent: true });
    return existing;
  }

  const { ok, data } = await postJson('/chats/direct', { nickname });
  if (!ok) {
    showError(socketStatus, `Не удалось открыть чат: ${data.error || 'неизвестно'}`);
    return null;
  }
  const chat = ensureChat(data.chat_id, data.peer_nickname || nickname);
  if (data.last_message_at) {
    chat.lastMessageAt = data.last_message_at;
  }
  renderChatList();
  if (navigate !== false) {
    navigateToChat(chat);
  }
  await joinChat(chat.id, { silent: true });
  return chat;
}

async function openChatFromRoute(peerToken) {
  let nickname = String(peerToken || '').trim();
  try {
    nickname = decodeURIComponent(nickname);
  } catch {
    nickname = String(peerToken || '').trim();
  }
  if (!nickname) return;
  const existing = findChatByPeer(nickname);
  if (existing) {
    await joinChat(existing.id, { silent: true });
    return;
  }
  await openDirectChat(nickname, { navigate: false });
}

function updateSocketStatus(message, type) {
  setStatus(socketStatus, message, type);
  setStatus(chatConnection, message, type);
}

function clearMessages() {
  if (messagesEl) {
    messagesEl.innerHTML = '';
  }
}

function scrollMessagesToBottom() {
  if (!messagesEl) return;
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function renderMessages(chatId) {
  clearMessages();
  const list = messagesByChat.get(String(chatId)) || [];
  list.forEach((message) => addMessageToUI(message));
  scrollMessagesToBottom();
}

function addMessageToUI(message, { system } = {}) {
  if (!messagesEl) return;
  const item = document.createElement('div');
  const meta = document.createElement('div');
  meta.className = 'meta';

  const bubble = document.createElement('div');
  bubble.className = 'bubble';

  const body = document.createElement('div');
  body.className = 'body';

  if (system) {
    item.className = 'message system';
    meta.textContent = 'Система';
    body.textContent =
      typeof message === 'string' ? message : 'Системное сообщение';
  } else {
    const isOwn =
      state.user && String(message.sender_user_id) === String(state.user.sub);
    item.className = `message ${isOwn ? 'outgoing' : 'incoming'}`;
    const time = formatTime(message.sent_at || new Date());
    const sender = isOwn ? 'Вы' : message.sender_nickname || 'Пользователь';
    const mode = message.decrypted ? 'расшифровано' : 'шифр';
    meta.textContent = `${sender} | ${time} | ${mode}`;
    body.textContent = message.decrypted || message.ciphertext || '';
  }

  bubble.appendChild(body);
  item.append(bubble, meta);
  messagesEl.appendChild(item);
  scrollMessagesToBottom();
}

function updateTypingStatus() {
  if (!typingStatus) return;
  if (!state.currentChatId) {
    setStatus(typingStatus, '');
    return;
  }
  if (typingUsers.size === 0) {
    setStatus(typingStatus, '');
    updateChatHeader(state.currentChatId);
    return;
  }
  const names = Array.from(typingUsers.values());
  setStatus(typingStatus, `${names.join(', ')} печатает...`);
  if (chatPeer) {
    chatPeer.textContent = 'печатает...';
  }
}

function emitTypingStart() {
  if (!socket || !socket.connected || !state.currentChatId) return;
  if (!isTyping) {
    socket.emit('typing:start', { chatId: state.currentChatId });
    isTyping = true;
  }
  if (typingTimer) {
    clearTimeout(typingTimer);
  }
  typingTimer = setTimeout(() => {
    emitTypingStop();
  }, 1200);
}

function emitTypingStop() {
  if (!socket || !socket.connected || !state.currentChatId) return;
  if (!isTyping) return;
  socket.emit('typing:stop', { chatId: state.currentChatId });
  isTyping = false;
}

async function joinChat(chatId, { silent } = {}) {
  if (!chatId) return;
  const id = String(chatId);
  let chat = ensureChat(id);
  if (!chat.peerNickname) {
    await loadChatsFromServer();
    chat = ensureChat(id);
  }
  state.currentChatId = id;
  setChatActive(true);
  updateChatHeader(id);
  renderChatList();
  typingUsers.clear();
  updateTypingStatus();
  renderMessages(id);
  await postJson(`/chats/${id}/join`, {});
  await loadChatHistory(id);
  if (socket?.connected) {
    socket.emit('chat:join', { chatId: id });
  }
  if (!silent) {
    addMessageToUI(`Вы вошли в чат с ${getChatDisplayName(chat)}`, { system: true });
  }

  if (chat.peerNickname) {
    const record = await ensureChatKey(id, chat.peerNickname);
    if (!record) {
      showError(chatConnection, 'Ключ чата не готов (нужно устройство собеседника).');
    }
  }
}

async function loadChatHistory(chatId) {
  if (!state.accessToken) return;
  const { ok, data } = await getJson(`/chats/${chatId}/messages?limit=50`);
  if (!ok || !data?.messages) {
    return;
  }
  const prevList = messagesByChat.get(String(chatId)) || [];
  const prevLastId = prevList.length ? prevList[prevList.length - 1].id : null;
  const messages = [];
  for (const message of data.messages) {
    const decrypted = await decryptForChat(chatId, message.ciphertext, message.nonce);
    messages.push({ ...message, decrypted });
  }
  const newLastId = messages.length ? messages[messages.length - 1].id : null;
  const changed =
    messages.length !== prevList.length || (newLastId && newLastId !== prevLastId);
  messagesByChat.set(String(chatId), messages);
  if (messages.length > 0) {
    const last = messages[messages.length - 1];
    const chat = ensureChat(chatId);
    const isOwn =
      state.user && String(last.sender_user_id) === String(state.user.sub);
    chat.lastMessageAt = last.sent_at || new Date().toISOString();
    const previewText = last.decrypted || last.ciphertext || '';
    chat.lastMessageText = isOwn ? `Вы: ${previewText}` : previewText;
    if (
      last.sender_nickname &&
      state.user &&
      !isOwn &&
      !chat.peerNickname
    ) {
      chat.peerNickname = last.sender_nickname;
      chat.title = last.sender_nickname;
    }
    if (state.user && !isOwn) {
      lastSeenByChat.set(String(chatId), last.sent_at || new Date().toISOString());
    }
    renderChatList();
    if (String(state.currentChatId) === String(chatId)) {
      updateChatHeader(chatId);
    }
  }
  if (changed && String(state.currentChatId) === String(chatId)) {
    renderMessages(chatId);
  }
}

async function handleIncomingMessage(payload) {
  if (!payload.chatId) return;
  const chatId = String(payload.chatId);
  const chat = ensureChat(chatId);
  if (
    payload.sender_nickname &&
    state.user &&
    String(payload.sender_user_id) !== String(state.user.sub) &&
    !chat.peerNickname
  ) {
    chat.peerNickname = payload.sender_nickname;
    chat.title = payload.sender_nickname;
  }
  if (!messagesByChat.has(chatId)) {
    messagesByChat.set(chatId, []);
  }

  const decrypted = await decryptForChat(chatId, payload.ciphertext, payload.nonce);
  const stored = { ...payload, decrypted };
  messagesByChat.get(chatId).push(stored);
  const isOwn =
    state.user && String(payload.sender_user_id) === String(state.user.sub);
  chat.lastMessageAt = payload.sent_at || new Date().toISOString();
  const previewText = decrypted || payload.ciphertext || '';
  chat.lastMessageText = isOwn ? `Вы: ${previewText}` : previewText;
  if (!isOwn) {
    lastSeenByChat.set(chatId, payload.sent_at || new Date().toISOString());
  }
  renderChatList();

  if (String(state.currentChatId) === chatId) {
    addMessageToUI(stored);
    updateChatHeader(chatId);
  }
}

function connectSocket() {
  if (!state.accessToken || typeof io !== 'function') {
    updateSocketStatus('Нет токена доступа', 'error');
    return;
  }

  if (socket) {
    socket.removeAllListeners();
    socket.disconnect();
  }

  const accessToken = state.accessToken;
  socket = io({
    path: `${BASE_PATH}/socket.io`,
    auth: { token: accessToken, deviceId: state.deviceId }
  });

  updateSocketStatus('Подключение...');

  socket.on('connect', () => {
    updateSocketStatus('Подключено', 'success');
    if (state.currentChatId) {
      joinChat(state.currentChatId, { silent: true }).catch(() => {});
    }
  });

  socket.on('disconnect', () => {
    updateSocketStatus('Отключено');
  });

  socket.on('connect_error', (err) => {
    updateSocketStatus(`Ошибка: ${err.message || 'connect_error'}`, 'error');
  });

  socket.on('typing:start', (payload = {}) => {
    if (String(payload.chatId) !== String(state.currentChatId)) return;
    const userId = String(payload.user_id || '');
    if (state.user && userId === String(state.user.sub)) return;
    typingUsers.set(userId, payload.nickname || 'Пользователь');
    updateTypingStatus();
  });

  socket.on('typing:stop', (payload = {}) => {
    if (String(payload.chatId) !== String(state.currentChatId)) return;
    const userId = String(payload.user_id || '');
    typingUsers.delete(userId);
    updateTypingStatus();
  });

  socket.on('message:new', (payload = {}) => {
    handleIncomingMessage(payload);
  });
}

function getCookieValue(name) {
  const match = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
  return match ? decodeURIComponent(match[2]) : '';
}

async function postJson(url, payload) {
  try {
    const headers = { 'Content-Type': 'application/json' };
    const csrfToken = state.csrfToken || getCookieValue('csrf_token');
    if (state.accessToken) {
      headers.authorization = `Bearer ${state.accessToken}`;
    }
    if (csrfToken) {
      headers['x-csrf-token'] = csrfToken;
      if (payload && typeof payload === 'object' && !payload.csrf_token) {
        payload.csrf_token = csrfToken;
      }
    }

    const response = await fetch(api(url), {
      method: 'POST',
      headers,
      credentials: 'same-origin',
      body: JSON.stringify(payload || {})
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { error: 'network_error' } };
  }
}

async function getJson(url) {
  try {
    const headers = {};
    if (state.accessToken) {
      headers.authorization = `Bearer ${state.accessToken}`;
    }
    const response = await fetch(api(url), {
      method: 'GET',
      headers,
      credentials: 'same-origin'
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { error: 'network_error' } };
  }
}

async function syncEpochFromServer() {
  if (!state.accessToken) return;
  const { ok, data } = await getJson('/me');
  if (!ok || !data?.epoch) {
    return;
  }
  await setAppValue('epoch', data.epoch);
  state.epoch = Number(data.epoch) || state.epoch;
}

async function clearIndexedDb() {
  dbPromise = null;
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => resolve();
  });
}

async function ensureDeviceRegistered() {
  await ensureEpoch();
  const identity = await ensureDeviceIdentity();
  if (!identity?.publicJwk) {
    showError(settingsStatus, 'Криптография недоступна. Нужен HTTPS или localhost.');
    return null;
  }
  const currentUserId = state.user?.sub ? String(state.user.sub) : null;
  const existingId = identity.deviceId;
  if (existingId && identity.userId && currentUserId && String(identity.userId) === currentUserId) {
    state.deviceId = existingId;
    return existingId;
  }
  if (existingId && currentUserId && String(identity.userId) !== currentUserId) {
    await saveDeviceId(null, currentUserId);
  }
  if (!state.accessToken) {
    return null;
  }

  const { ok, data } = await postJson('/devices/register', {
    name: 'Web device',
    pubkey: identity.publicJwk
  });
  if (!ok) {
    showError(
      settingsStatus,
      `Регистрация устройства не удалась: ${data.error || 'неизвестно'}`
    );
    return null;
  }

  if (data.device_id) {
    await saveDeviceId(data.device_id, currentUserId);
    return data.device_id;
  }
  return null;
}

async function fetchPeerDeviceKey(nickname) {
  if (!state.accessToken) {
    showError(settingsStatus, 'Нужен вход, чтобы получить ключи собеседника.');
    return null;
  }
  const { ok, data } = await getJson(
    `/devices/public?nickname=${encodeURIComponent(nickname)}`
  );
  if (!ok) {
    showError(settingsStatus, `Не удалось получить ключи: ${data.error || 'неизвестно'}`);
    return null;
  }
  if (!data.devices || data.devices.length === 0) {
    showError(settingsStatus, 'У собеседника нет зарегистрированных устройств.');
    return null;
  }
  const device = data.devices[0];
  let publicJwk = device.pubkey;
  if (typeof publicJwk === 'string') {
    try {
      publicJwk = JSON.parse(publicJwk);
    } catch {
      showError(settingsStatus, 'Неверный формат публичного ключа собеседника.');
      return null;
    }
  }

  await storeTrustedContact(nickname, device.id, publicJwk);
  return {
    deviceId: device.id,
    publicJwk,
    nickname
  };
}

async function handleAuth(token) {
  if (!token) return;
  setAccessToken(token);
  setAuthVisible(false);
  await syncEpochFromServer();
  await ensureDeviceRegistered();
  await loadChatsFromServer();
  connectSocket();
}

function stopPairingPoll() {
  if (pairingState.pollTimer) {
    clearInterval(pairingState.pollTimer);
    pairingState.pollTimer = null;
  }
}

function setPairingStatus(target, message, type) {
  setStatus(target, message, type);
}

async function startPairingAsNewDevice() {
  if (!state.accessToken) {
    showError(settingsStatus, 'Нужен вход.');
    return;
  }
  if (!ensureCryptoAvailable(settingsStatus)) {
    return;
  }
  await ensureDeviceRegistered();

  const tempKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', tempKeyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', tempKeyPair.privateKey);

  const { ok, data } = await postJson('/pairings/start', {
    pubkey_new: publicJwk,
    device_id_new: state.deviceId
  });
  if (!ok) {
    showError(settingsStatus, `Не удалось начать подключение: ${data.error || 'неизвестно'}`);
    return;
  }

  const pairingId = data.pairing_id;
  pairingState.newDevice = {
    pairingId,
    publicJwk,
    privateJwk,
    pairingKey: null,
    verified: false
  };
  pairingState.oldDevice = null;
  stopPairingPoll();

  const payload = JSON.stringify({ pairingId, pubkey_new: publicJwk });
  if (pairingQrText) {
    pairingQrText.textContent = payload;
  }
  if (pairingQrBlock) {
    pairingQrBlock.classList.remove('is-hidden');
  }
  if (pairingQrImage) {
    const qrResp = await postJson('/pairings/qr', { text: payload });
    if (qrResp.ok && qrResp.data?.qr_data_url) {
      pairingQrImage.src = qrResp.data.qr_data_url;
    } else {
      pairingQrImage.removeAttribute('src');
    }
  }
  setPairingStatus(pairingCodeNew, 'Ожидание старого устройства...', '');

  pairingState.pollTimer = setInterval(async () => {
    if (!pairingState.newDevice?.pairingId) return;
    const status = await getJson(`/pairings/${pairingState.newDevice.pairingId}`);
    if (!status.ok) {
      return;
    }
    const payloadData = status.data;
    if (payloadData.pubkey_old && !pairingState.newDevice.pairingKey) {
      let peerPublicJwk = payloadData.pubkey_old;
      if (typeof peerPublicJwk === 'string') {
        try {
          peerPublicJwk = JSON.parse(peerPublicJwk);
        } catch {
          return;
        }
      }
      const pairingKey = await derivePairingKey({
        privateJwk: pairingState.newDevice.privateJwk,
        peerPublicJwk,
        pairingId: pairingState.newDevice.pairingId
      });
      pairingState.newDevice.pairingKey = pairingKey;
      const code = await computePairingCode(pairingKey, pairingState.newDevice.pairingId);
      setPairingStatus(pairingCodeNew, `Сверьте код: ${code}`, 'success');
    }

    if (payloadData.payload_ciphertext && pairingState.newDevice?.pairingKey) {
      const decrypted = await decryptPairingPayload(
        pairingState.newDevice.pairingKey,
        payloadData.payload_ciphertext,
        payloadData.payload_nonce
      );
      if (decrypted) {
        const ok = await importKeyMaterial(decrypted);
        if (ok) {
          renderChatList();
          setPairingStatus(
            pairingCodeNew,
            'Подключение завершено. Ключи импортированы.',
            'success'
          );
          stopPairingPoll();
        }
      }
    }
  }, 2000);
}

async function decryptPairingPayload(pairingKey, ciphertext, nonce) {
  try {
    if (!ciphertext || !nonce) {
      return null;
    }
    const buffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(nonce) },
      pairingKey,
      base64ToBytes(ciphertext)
    );
    const json = new TextDecoder().decode(buffer);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

async function acceptPairingAsOldDevice() {
  if (!state.accessToken) {
    showError(settingsStatus, 'Нужен вход.');
    return;
  }
  if (!ensureCryptoAvailable(settingsStatus)) {
    return;
  }
  const raw = pairingInput?.value.trim();
  if (!raw) {
    showError(pairingTransferStatus, 'Вставьте данные подключения.');
    return;
  }
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    showError(pairingTransferStatus, 'Неверный JSON.');
    return;
  }
  if (!payload.pairingId || !payload.pubkey_new) {
    showError(pairingTransferStatus, 'Не хватает pairingId или pubkey_new.');
    return;
  }

  const tempKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', tempKeyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', tempKeyPair.privateKey);

  const { ok, data } = await postJson('/pairings/accept', {
    pairingId: payload.pairingId,
    pubkey_old: publicJwk
  });
  if (!ok) {
    showError(pairingTransferStatus, `Не удалось принять: ${data.error || 'неизвестно'}`);
    return;
  }

  const pairingKey = await derivePairingKey({
    privateJwk,
    peerPublicJwk: payload.pubkey_new,
    pairingId: payload.pairingId
  });
  const code = await computePairingCode(pairingKey, payload.pairingId);

  pairingState.oldDevice = {
    pairingId: payload.pairingId,
    publicJwk,
    privateJwk,
    pairingKey,
    verifyCode: code
  };
  pairingState.newDevice = null;

  setPairingStatus(pairingCodeOld, `Сверьте код: ${code}`, 'success');
  setPairingStatus(
    pairingTransferStatus,
    'Если коды совпадают, подтвердите отправку ключей.',
    ''
  );
}

async function sendPairingPayload() {
  if (!pairingState.oldDevice?.pairingKey) {
    showError(pairingTransferStatus, 'Сначала примите подключение.');
    return;
  }

  const payload = await exportKeyMaterial();
  const json = JSON.stringify(payload);
  const nonce = randomBase64(12);
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: base64ToBytes(nonce) },
    pairingState.oldDevice.pairingKey,
    textEncoder.encode(json)
  );
  const ciphertext = bufferToBase64(cipherBuffer);

  const { ok, data } = await postJson('/pairings/transfer', {
    pairingId: pairingState.oldDevice.pairingId,
    ciphertext,
    nonce,
    verify_code: pairingState.oldDevice.verifyCode,
    meta: { version: 1, exported_at: payload.exported_at }
  });
  if (!ok) {
    showError(pairingTransferStatus, `Передача не удалась: ${data.error || 'неизвестно'}`);
    return;
  }
  showSuccess(pairingTransferStatus, 'Ключи отправлены. Завершите подключение на новом устройстве.');
}

async function createLoginCodeForAuth() {
  if (!state.accessToken) {
    showError(loginCodeStatus, 'Нужен вход.');
    return;
  }
  if (!ensureCryptoAvailable(loginCodeStatus)) {
    return;
  }

  const code = generateLoginCode();
  const payload = await exportKeyMaterial();
  const encrypted = await encryptLoginPayload(code, payload);
  const { ok, data } = await postJson('/auth/login-code', {
    code,
    payload_ciphertext: encrypted.ciphertext,
    payload_nonce: encrypted.nonce,
    payload_meta: encrypted.meta
  });
  if (!ok) {
    showError(loginCodeStatus, `Не удалось создать код: ${data.error || 'неизвестно'}`);
    return;
  }

  if (loginCodeValue) {
    loginCodeValue.textContent = code;
  }
  const expiresAt = data?.expires_at ? new Date(data.expires_at) : null;
  const expiresLabel = expiresAt && !Number.isNaN(expiresAt.getTime())
    ? expiresAt.toLocaleString()
    : 'скоро';
  showSuccess(loginCodeStatus, `Код создан. Действует до ${expiresLabel}.`);
}

registerForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const nickname = registerNickname.value.trim();
  setStatus(registerStatus, '');
  setStatus(verifyStatus, '');
  loginOutput.textContent = '';
  qrBlock.classList.add('is-hidden');
  qrImage.removeAttribute('src');
  otpauthUrl.textContent = '';

  if (!nickname) {
    showError(registerStatus, 'Введите ник.');
    return;
  }

  const { ok, data } = await postJson('/auth/register', { nickname });
  if (!ok) {
    showError(registerStatus, `Регистрация не удалась: ${data.error || 'неизвестно'}`);
    return;
  }

  qrImage.src = data.qr_data_url;
  otpauthUrl.textContent = data.otpauth_url;
  qrBlock.classList.remove('is-hidden');

  verifyNickname.value = nickname;
  loginNickname.value = nickname;

  showSuccess(registerStatus, 'QR готов. Отсканируйте в Authenticator и подтвердите.');
});

verifyForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const nickname = verifyNickname.value.trim();
  const code = normalizeCode(verifyCode.value);
  setStatus(verifyStatus, '');

  if (!nickname || !code) {
    showError(verifyStatus, 'Введите ник и код.');
    return;
  }

  const { ok, data } = await postJson('/auth/register/verify', { nickname, code });
  if (!ok) {
    showError(verifyStatus, `Подтверждение не удалось: ${data.error || 'неизвестно'}`);
    return;
  }

  showSuccess(verifyStatus, 'TOTP включен. Теперь можно войти.');
});

loginForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const nickname = loginNickname.value.trim();
  const code = normalizeCode(loginCode.value);
  const oneTimeCode = normalizeCode(loginOneTime.value);
  setStatus(loginStatus, '');
  loginOutput.textContent = '';

  if (!nickname || !code) {
    showError(loginStatus, 'Введите ник и код.');
    return;
  }

  const payload = { nickname, code };
  if (oneTimeCode) {
    payload.login_code = oneTimeCode;
  }

  const { ok, data } = await postJson('/auth/login', payload);
  if (!ok) {
    const message =
      data.error === 'login_code_required'
        ? 'Нужен одноразовый код для входа.'
        : `Вход не удался: ${data.error || 'неизвестно'}`;
    showError(loginStatus, message);
    return;
  }

  if (data.csrf_token) {
    await setCsrfToken(data.csrf_token);
  }

  showSuccess(loginStatus, 'Вход выполнен.');
  loginOutput.textContent = JSON.stringify(data, null, 2);

  if (data.login_payload && oneTimeCode) {
    if (!ensureCryptoAvailable(loginStatus)) {
      showError(loginStatus, 'Нужен HTTPS, чтобы расшифровать ключи.');
    } else {
      const decrypted = await decryptLoginPayload(oneTimeCode, data.login_payload);
      if (decrypted) {
        await importKeyMaterial(decrypted);
        renderChatList();
      } else {
        showError(loginStatus, 'Не удалось расшифровать ключи. Проверьте код входа.');
      }
    }
  }

  if (data.access_token) {
    await handleAuth(data.access_token);
    navigateTo('#/chats');
  }
  loginOneTime.value = '';
});

async function refreshSession({ silent } = {}) {
  if (!silent) {
    setStatus(refreshStatus, '');
    refreshOutput.textContent = '';
  }

  const { ok, data } = await postJson('/auth/refresh', {});
  if (!ok) {
    if (!silent) {
      showError(refreshStatus, `Обновление не удалось: ${data.error || 'неизвестно'}`);
    }
    return;
  }

  if (data.csrf_token) {
    await setCsrfToken(data.csrf_token);
  }

  if (data.access_token) {
    await handleAuth(data.access_token);
  }

  if (!silent) {
    showSuccess(refreshStatus, 'Сессия обновлена.');
    refreshOutput.textContent = JSON.stringify(data, null, 2);
  } else if (data.access_token) {
    loginOutput.textContent = JSON.stringify(data, null, 2);
    showSuccess(loginStatus, 'Сессия восстановлена через refresh.');
    if (parseRoute().name === 'auth') {
      navigateTo('#/chats');
    }
  }
}

refreshForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  await refreshSession();
});

menuBtn?.addEventListener('click', () => {
  openModal(menuModal);
});

menuCloseEls.forEach((el) => {
  el.addEventListener('click', () => closeModal(menuModal));
});

openSettingsBtn?.addEventListener('click', () => {
  closeModal(menuModal);
  openModal(settingsModal);
});

settingsCloseEls.forEach((el) => {
  el.addEventListener('click', () => closeModal(settingsModal));
});

chatSearchInput?.addEventListener('input', () => {
  state.searchTerm = chatSearchInput.value;
  renderChatList();
});

attachBtn?.addEventListener('click', (event) => {
  event.stopPropagation();
  if (!attachMenu) return;
  attachMenu.classList.toggle('is-hidden');
});

attachMenu?.addEventListener('click', (event) => {
  const action = event.target.closest('button')?.dataset.attach;
  if (!action) return;
  if (action === 'image') {
    attachImageInput?.click();
  } else if (action === 'document') {
    attachDocInput?.click();
  }
  attachMenu.classList.add('is-hidden');
});

attachImageInput?.addEventListener('change', () => {
  const file = attachImageInput.files?.[0] || null;
  updateAttachmentStatus(file);
});

attachDocInput?.addEventListener('change', () => {
  const file = attachDocInput.files?.[0] || null;
  updateAttachmentStatus(file);
});

document.addEventListener('click', (event) => {
  if (!attachMenu || attachMenu.classList.contains('is-hidden')) return;
  const target = event.target;
  if (target instanceof Element) {
    const wrapper = target.closest('.attach-wrapper');
    if (!wrapper) {
      attachMenu.classList.add('is-hidden');
    }
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  closeModal(menuModal);
  closeModal(settingsModal);
  attachMenu?.classList.add('is-hidden');
});

chatCreateForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const peerNickname = newChatPeerInput?.value.trim();
  if (!peerNickname) {
    showError(socketStatus, 'Введите ник собеседника.');
    return;
  }
  navigateTo(`#/chat/${encodeURIComponent(peerNickname)}`);
  if (newChatPeerInput) newChatPeerInput.value = '';
});

chatBack?.addEventListener('click', () => {
  navigateTo('#/chats');
});

messageInput?.addEventListener('input', () => {
  if (!messageInput.value.trim()) {
    emitTypingStop();
    return;
  }
  emitTypingStart();
});

messageInput?.addEventListener('blur', () => {
  emitTypingStop();
});

messageForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!socket || !socket.connected) {
    updateSocketStatus('Сокет не подключен.', 'error');
    return;
  }

  const text = messageInput.value.trim();
  if (!text) {
    return;
  }

  if (!state.currentChatId) {
    updateSocketStatus('Сначала откройте чат.', 'error');
    return;
  }

  if (!state.deviceId) {
    updateSocketStatus('Устройство не зарегистрировано.', 'error');
    return;
  }

  const chat = state.chats.find((item) => item.id === state.currentChatId);
  if (chat?.peerNickname) {
    await ensureChatKey(state.currentChatId, chat.peerNickname);
  }

  const encrypted = await encryptForChat(state.currentChatId, text);
  if (!encrypted) {
    updateSocketStatus(
      'Нет ключа чата. Проверьте ник собеседника и импорт ключей.',
      'error'
    );
    return;
  }

  const payload = {
    chatId: state.currentChatId,
    ...encrypted
  };

  socket.emit('message:send', payload, (ack) => {
    if (ack && !ack.ok) {
      updateSocketStatus(`Отправка не удалась: ${ack.error || 'неизвестно'}`, 'error');
    }
  });

  messageInput.value = '';
  if (attachImageInput) attachImageInput.value = '';
  if (attachDocInput) attachDocInput.value = '';
  updateAttachmentStatus(null);
  emitTypingStop();
});

pairingStartBtn?.addEventListener('click', async () => {
  setPairingStatus(pairingTransferStatus, '');
  setPairingStatus(pairingCodeOld, '');
  setPairingStatus(pairingCodeNew, '');
  await startPairingAsNewDevice();
});

pairingAcceptBtn?.addEventListener('click', async () => {
  await acceptPairingAsOldDevice();
});

pairingConfirmBtn?.addEventListener('click', async () => {
  await sendPairingPayload();
});

loginCodeBtn?.addEventListener('click', async () => {
  setStatus(loginCodeStatus, '');
  await createLoginCodeForAuth();
});

async function resetKeys() {
  if (!state.accessToken) {
    showError(settingsStatus, 'Нужен вход.');
    return;
  }
  const confirmed = window.confirm(
    'Сбросить ключи? Это удалит локальные ключи и отзовет сессии/устройства.'
  );
  if (!confirmed) {
    return;
  }

  const token = state.accessToken;
  const { ok, data } = await postJson('/auth/reset', {});
  if (!ok) {
    showError(settingsStatus, `Сброс не удался: ${data.error || 'неизвестно'}`);
    return;
  }

  stopPairingPoll();
  messagesByChat.clear();
  typingUsers.clear();
  lastSeenByChat.clear();
  state.chats = [];
  state.currentChatId = null;
  clearMessages();
  setChatActive(false);
  updateChatHeader(null);
  if (chatSearchInput) {
    chatSearchInput.value = '';
    state.searchTerm = '';
  }
  renderChatList();
  updateTypingStatus();

  clearAuth();
  await clearIndexedDb();
  await openDb();
  await setAppValue('epoch', data.epoch || 1);
  state.epoch = Number(data.epoch) || 1;

  if (token) {
    await handleAuth(token);
  }
  navigateTo('#/chats');
  closeModal(settingsModal);
  showSuccess(settingsStatus, 'Сброс завершен.');
}

changePointBtn?.addEventListener('click', async () => {
  await resetKeys();
});

logoutBtn?.addEventListener('click', async () => {
  await postJson('/auth/logout', {});
  clearAuth();
  closeModal(settingsModal);
  closeModal(menuModal);
  navigateTo('#/auth');
});

function handleRouteChange() {
  const route = parseRoute();
  if (route.name === 'auth') {
    setAuthVisible(true);
    return;
  }

  if (!state.accessToken) {
    setAuthVisible(true);
    return;
  }

  setAuthVisible(false);

  if (route.name === 'chat') {
    if (!route.peer) {
      navigateTo('#/chats');
      return;
    }
    openChatFromRoute(route.peer).catch(() => {});
  } else {
    state.currentChatId = null;
    setChatActive(false);
    updateChatHeader(null);
    renderChatList();
  }
}

window.addEventListener('hashchange', handleRouteChange);

async function initApp() {
  await ensureEpoch();
  if (!cryptoAvailable()) {
    showError(
      cryptoWarning,
      'Для Web Crypto нужен безопасный контекст (HTTPS или localhost).'
    );
  }
  state.csrfToken = await getAppValue('csrfToken', '');
  await ensureDeviceIdentity();
  await getDeviceId();
  await loadChatsFromStorage();
  updateUserUI();
  await refreshSession({ silent: true });
  handleRouteChange();
}

initApp();
