# Правила системы

## Base Path
- Все HTTP и WS запросы идут с префиксом `/vladogram`.
- Статика подключается относительными путями (например, `styles.css`, `app.js`).
- Socket.IO path: `/vladogram/socket.io`.

## Реалтайм
- Протокол: WebSocket; для старта использовать Socket.IO.
- WS handshake проверяет access JWT.
- Комнаты: по chatId и userId.

## Ключи сообщений
- Генерация ключей: только на клиенте.
- Хранение ключей: IndexedDB.
- Сервер хранит только {ciphertext, nonce, meta}, plaintext не сохраняется.

## E2E v1
- Схема: ECDH (P-256) + HKDF + AES-GCM.
- Нонсы уникальные (счётчик + случайность).
- Meta минимум: senderDeviceId, epoch, counter.

## Авторизация
- Формат: nickname + TOTP (Google Authenticator).
- TOTP коды меняются по времени.

## Сессии
- Access: JWT 5–15 минут.
- Refresh: 30–90 дней, хранить в БД хэш, raw не хранить.
- Refresh cookie: HttpOnly, SameSite=Lax, Path=/vladogram; Secure в проде.
- CSRF cookie: HttpOnly, SameSite=Lax, Path=/vladogram; Secure в проде.
- CSRF токен выдаётся в JSON и хранится на клиенте, отправляется в заголовке/теле.
- /auth/refresh → новый access, /auth/logout → revoke refresh.

## Мульти-девайс
- Только через QR-пэйринг.
- Устройства регистрируют публичный ключ (ECDH) на сервере.
- Получение публичных ключей собеседника через /devices/public.

## «Изменить точку»
- Клиент полностью очищает IndexedDB (ключи, chatKeys, кэш).
- Сервер удаляет сообщения пользователя и членство в чатах.
- Сервер ревокает все refresh-сессии.
- Сервер инвалидирует устройства (требуется новый pairing).
- Сервер увеличивает epoch пользователя.
- Клиент генерирует новый identity key и начинает с чистого листа.

## Pairing (QR)
- Новое устройство: логин → временная ECDH пара → pairingId → QR {pairingId, pubkey_new}.
- Старое устройство: принимает QR → отправляет pubkey_old_temp.
- Оба устройства: ECDH → pairingChannelKey → код-сравнение (6 цифр).
- Старое устройство шифрует и отправляет ключевой материал (chatKeys, trustedContacts, epoch).

## Чаты и история
- Членство в чате фиксируется (chat_members).
- История доступна только участникам.
