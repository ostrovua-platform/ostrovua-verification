// ═══════════════════════════════════════════════════════════════════
//  Apple Push Notification service (APNs), HTTP/2 + JWT (ES256).
//  Без зовнішніх бібліотек: тільки вбудовані http2 / crypto.
//
//  Потрібні змінні оточення:
//    APNS_KEY_ID     — ID ключа (.p8) з Apple Developer
//    APNS_TEAM_ID    — Team ID
//    APNS_BUNDLE_ID  — com.ostrovua.app
//    APNS_KEY_PATH   — шлях до AuthKey_XXXX.p8 (у контейнері)
//    APNS_ENV        — production | sandbox   (TestFlight = production)
//
//  Приватність: у тексті push немає жодних персональних даних
//  документа. Лише те, що людина й так бачить у застосунку.
// ═══════════════════════════════════════════════════════════════════
const http2 = require('http2');
const crypto = require('crypto');
const fs = require('fs');

const KEY_ID    = process.env.APNS_KEY_ID    || '';
const TEAM_ID   = process.env.APNS_TEAM_ID   || '';
const BUNDLE_ID = process.env.APNS_BUNDLE_ID || 'com.ostrovua.app';
const KEY_PATH  = process.env.APNS_KEY_PATH  || '/app/certs/apns.p8';
const APNS_ENV  = process.env.APNS_ENV       || 'production';

// Хост обирається ПО КОЖНОМУ токену: пристрій каже при реєстрації,
// з якого він середовища (білд з Xcode = sandbox, TestFlight/App Store =
// production). Слати sandbox-токен у production-хост — BadDeviceToken.
const hostFor = (env) =>
  (env || APNS_ENV) === 'sandbox'
    ? 'https://api.sandbox.push.apple.com'
    : 'https://api.push.apple.com';

let privateKey = null;
try {
  if (fs.existsSync(KEY_PATH)) privateKey = fs.readFileSync(KEY_PATH, 'utf8');
} catch (e) {
  console.warn('[apns] не прочитав ключ:', e.message);
}

const configured = () => Boolean(privateKey && KEY_ID && TEAM_ID);

// JWT для APNs (ES256). Кешуємо: Apple дозволяє оновлювати раз на 20 хв.
let cachedToken = null;
let cachedAt = 0;

function providerToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && now - cachedAt < 1500) return cachedToken;

  const header  = { alg: 'ES256', kid: KEY_ID };
  const payload = { iss: TEAM_ID, iat: now };

  const b64 = (obj) =>
    Buffer.from(JSON.stringify(obj)).toString('base64url');

  const unsigned = `${b64(header)}.${b64(payload)}`;
  const signature = crypto
    .createSign('SHA256')
    .update(unsigned)
    .sign({ key: privateKey, dsaEncoding: 'ieee-p1363' })
    .toString('base64url');

  cachedToken = `${unsigned}.${signature}`;
  cachedAt = now;
  return cachedToken;
}

/**
 * Надіслати push на один пристрій.
 * @returns {Promise<{ok: boolean, status: number, reason?: string}>}
 */
function sendPush(deviceToken, { title, body, badge, data, environment }) {
  return new Promise((resolve) => {
    if (!configured()) {
      return resolve({ ok: false, status: 0, reason: 'APNS not configured' });
    }

    const client = http2.connect(hostFor(environment));
    client.on('error', (e) =>
      resolve({ ok: false, status: 0, reason: e.message })
    );

    const payload = JSON.stringify({
      aps: {
        alert: { title, body },
        sound: 'default',
        ...(typeof badge === 'number' ? { badge } : {}),
      },
      ...(data || {}),
    });

    const req = client.request({
      ':method': 'POST',
      ':path': `/3/device/${deviceToken}`,
      authorization: `bearer ${providerToken()}`,
      'apns-topic': BUNDLE_ID,
      'apns-push-type': 'alert',
      'apns-priority': '10',
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload),
    });

    let status = 0;
    let chunks = '';

    req.on('response', (headers) => { status = headers[':status']; });
    req.on('data', (c) => { chunks += c; });
    req.on('end', () => {
      client.close();
      if (status === 200) return resolve({ ok: true, status });

      let reason = chunks;
      try { reason = JSON.parse(chunks).reason || chunks; } catch (e) {}
      resolve({ ok: false, status, reason });
    });

    req.setTimeout(10000, () => {
      req.close();
      client.close();
      resolve({ ok: false, status: 0, reason: 'timeout' });
    });

    req.end(payload);
  });
}

/**
 * VoIP-push (PushKit): будить застосунок і дзвонить ЯК ДЗВІНОК через
 * CallKit — навіть із заблокованим екраном. Той самий ключ .p8,
 * але topic = <bundle>.voip і apns-push-type = voip.
 */
function sendVoipPush(deviceToken, { payload, environment }) {
  return new Promise((resolve) => {
    if (!configured()) {
      return resolve({ ok: false, status: 0, reason: 'APNS not configured' });
    }

    const client = http2.connect(hostFor(environment));
    client.on('error', (e) =>
      resolve({ ok: false, status: 0, reason: e.message })
    );

    const body = JSON.stringify(payload || {});

    const req = client.request({
      ':method': 'POST',
      ':path': `/3/device/${deviceToken}`,
      authorization: `bearer ${providerToken()}`,
      'apns-topic': `${BUNDLE_ID}.voip`,
      'apns-push-type': 'voip',
      'apns-priority': '10',
      // Дзвінок актуальний лише ~30 с — далі Apple його просто викидає.
      'apns-expiration': String(Math.floor(Date.now() / 1000) + 30),
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
    });

    let status = 0;
    let chunks = '';

    req.on('response', (headers) => { status = headers[':status']; });
    req.on('data', (c) => { chunks += c; });
    req.on('end', () => {
      client.close();
      if (status === 200) return resolve({ ok: true, status });

      let reason = chunks;
      try { reason = JSON.parse(chunks).reason || chunks; } catch (e) {}
      resolve({ ok: false, status, reason });
    });

    req.setTimeout(10000, () => {
      req.close();
      client.close();
      resolve({ ok: false, status: 0, reason: 'timeout' });
    });

    req.end(body);
  });
}

module.exports = { configured, sendPush, sendVoipPush, APNS_ENV };
