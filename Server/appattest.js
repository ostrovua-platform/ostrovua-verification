/**
 * Apple App Attest — перевірка attestation (реєстрація ключа) та assertion
 * (кожен аппрув верифікації). Docs: developer.apple.com/documentation/devicecheck
 *
 * Потрібно:
 *   ENV  APPLE_TEAM_ID, APP_BUNDLE_ID, APPATTEST_ENV=production|development
 *   Файл certs/Apple_App_Attestation_Root_CA.pem (корінь Apple; завантажити:
 *   curl -O https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem)
 */

'use strict';

const crypto = require('crypto');
const cbor   = require('cbor');
const fs     = require('fs');
const path   = require('path');

const TEAM_ID    = process.env.APPLE_TEAM_ID  || '';
const BUNDLE_ID  = process.env.APP_BUNDLE_ID  || '';
// FAIL-CLOSED (аудит P1-08): будь-яке значення, крім явного
// 'development', трактується як 'production' — одрук у конфігу
// не відкриває приймання dev-атестацій.
const ATT_ENV    = process.env.APPATTEST_ENV === 'development' ? 'development' : 'production';
const APP_ID     = `${TEAM_ID}.${BUNDLE_ID}`;

// правильна назва — Attestation; стару лишаємо як fallback
const ROOT_CA_CANDIDATES = [
  path.join(__dirname, 'certs', 'Apple_App_Attestation_Root_CA.pem'),
  path.join(__dirname, 'certs', 'Apple_App_Attest_Root_CA.pem'),
];
let ROOT_CA = null;
for (const p of ROOT_CA_CANDIDATES) {
  try {
    const pem = fs.readFileSync(p, 'utf8');
    if (!pem.includes('BEGIN CERTIFICATE')) continue;   // захист від HTML-404
    ROOT_CA = new crypto.X509Certificate(pem);
    break;
  } catch (e) { /* наступний кандидат */ }
}
if (!ROOT_CA) {
  console.warn('[appattest] Root CA не завантажено (%s) — attestation неможлива.',
    ROOT_CA_CANDIDATES[0]);
}

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

function strictBase64(value, maxBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length > Math.ceil(maxBytes / 3) * 4 + 4) {
    throw new Error('Некоректний base64');
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.length > maxBytes) throw new Error('Завеликий payload');
  return decoded;
}

function configured() {
  return Boolean(ROOT_CA && TEAM_ID && BUNDLE_ID);
}

// ── CHALLENGES (одноразові nonce, прив'язані до користувача) ─────────────────
const challenges = new Map(); // id -> { contributorId, purpose, bytes, expiresAt }
const ATTESTATION_CHALLENGE_TTL_MS = 5 * 60 * 1000;
// Liveness and document proof nonces are issued immediately before the
// corresponding physical operation. Keeping their authority window separate
// from App Attest registration materially reduces real-time relay exposure.
const LIVENESS_CHALLENGE_TTL_MS = 90 * 1000;
const DOCUMENT_CHALLENGE_TTL_MS = 90 * 1000;
const MAX_CHALLENGES = 5000;         // жорсткий ліміт памʼяті (аудит P1-02)
const MAX_PER_CONTRIBUTOR = 8;       // анти-флуд на один акаунт

// Протухлі челенджі раніше висіли в памʼяті вічно — прибираємо щохвилини
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) if (now > c.expiresAt) challenges.delete(id);
}, 60 * 1000).unref();

function issueChallenge(contributorId, purpose = 'attestation') {
  if (![
    'attestation',
    'liveness',
    'liveness_calibration',
    'document_auth',
    'document_auth_calibration',
  ].includes(purpose)) {
    throw new Error('invalid challenge purpose');
  }
  // Ліміт на акаунт: витісняємо НАЙСТАРІШІ свої (аудит P1-06 —
  // попередня версія помилково видаляла найновіші).
  const mine = [];
  for (const [id, c] of challenges) {
    if (c.contributorId === contributorId) mine.push(id); // Map = порядок вставки
  }
  while (mine.length >= MAX_PER_CONTRIBUTOR) {
    challenges.delete(mine.shift());
  }
  // Глобальний ліміт: fail-closed, а не безмежне зростання памʼяті
  if (challenges.size >= MAX_CHALLENGES) {
    const now = Date.now();
    for (const [id, c] of challenges) if (now > c.expiresAt) challenges.delete(id);
    if (challenges.size >= MAX_CHALLENGES) throw new Error('Челенджі вичерпано, спробуй пізніше');
  }

  const id    = crypto.randomBytes(16).toString('base64url');
  const bytes = crypto.randomBytes(32);
  const ttlMs = purpose.startsWith('document_auth')
    ? DOCUMENT_CHALLENGE_TTL_MS
    : purpose.startsWith('liveness')
      ? LIVENESS_CHALLENGE_TTL_MS
      : ATTESTATION_CHALLENGE_TTL_MS;
  const expiresAt = Date.now() + ttlMs;
  challenges.set(id, {
    contributorId,
    purpose,
    bytes,
    expiresAt,
  });
  return {
    id,
    challenge: bytes.toString('base64'),
    expiresAt: new Date(expiresAt).toISOString(),
    expiresInSeconds: Math.floor(ttlMs / 1000),
  };
}

function consumeChallenge(id, contributorId, purpose = 'attestation') {
  const c = challenges.get(id);
  if (!c) return null;
  // ВЛАСНИК перевіряється ДО видалення (аудит P1-06): чужий запит
  // не «спалює» челендж легітимного власника.
  if (c.contributorId !== contributorId || c.purpose !== purpose) return null;
  challenges.delete(id);                        // одноразовий для власника
  if (Date.now() > c.expiresAt) return null;
  return c.bytes;
}

// Read-only binding check for multi-step protocols such as server-owned Chip
// Authentication. The document challenge remains reserved for the final
// /approve transaction; callers receive a copy so they cannot mutate the
// in-memory challenge. It is still consumed exactly once by /approve.
function inspectChallenge(id, contributorId, purpose = 'attestation') {
  const c = challenges.get(id);
  if (!c || c.contributorId !== contributorId || c.purpose !== purpose) return null;
  if (Date.now() > c.expiresAt) {
    challenges.delete(id);
    return null;
  }
  return Buffer.from(c.bytes);
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challenges) if (now > v.expiresAt) challenges.delete(k);
}, 60 * 1000).unref();

// ── ВИТЯГ NONCE З СЕРТИФІКАТА (розширення OID 1.2.840.113635.100.8.2) ────────
// ASN.1: OCTET STRING( SEQ( [1] OCTET STRING(32 bytes nonce) ) ).
// Шукаємо OID у DER і беремо 32 байти після маркера 04 20 у межах розширення.
const APPATTEST_NONCE_OID = Buffer.from('06092a864886f7636408 02'.replace(/ /g, ''), 'hex');

function extractCertNonce(certDer) {
  const idx = certDer.indexOf(APPATTEST_NONCE_OID);
  if (idx < 0) return null;
  // в межах ~64 байтів після OID: тег 04 (OCTET STRING) довжини 0x20
  for (let i = idx + APPATTEST_NONCE_OID.length; i < Math.min(idx + 80, certDer.length - 34); i++) {
    if (certDer[i] === 0x04 && certDer[i + 1] === 0x20) {
      // переконуємось, що це САМЕ внутрішній octet string (перед ним контекстний тег A1)
      if (certDer[i - 2] === 0xa1 || certDer[i - 3] === 0xa1) {
        return certDer.subarray(i + 2, i + 34);
      }
    }
  }
  return null;
}

// SPKI DER (P-256) → 65-байтна нестиснута точка (Apple keyId = SHA256 точки).
function ecPointFromSpki(spkiDer) {
  const point = spkiDer.subarray(spkiDer.length - 65);
  if (point[0] !== 0x04) throw new Error('Unexpected SPKI: no uncompressed EC point');
  return point;
}

function parseAuthData(authData) {
  if (!Buffer.isBuffer(authData) || authData.length < 37) throw new Error('authenticatorData закороткий');
  const hasCredential = authData.length >= 55;
  const credentialLength = hasCredential ? authData.readUInt16BE(53) : 0;
  if (hasCredential && 55 + credentialLength > authData.length) throw new Error('credentialId обрізаний');
  return {
    rpIdHash:  authData.subarray(0, 32),
    flags:     authData[32],
    counter:   authData.readUInt32BE(33),
    aaguid:    authData.length >= 53 ? authData.subarray(37, 53) : null,
    credIdLen: credentialLength,
    credId:    hasCredential ? authData.subarray(55, 55 + credentialLength) : null,
  };
}

const AAGUID_PROD = Buffer.from('appattest\0\0\0\0\0\0\0', 'ascii');
const AAGUID_DEV  = Buffer.from('appattestdevelop', 'ascii');

// ── ATTESTATION: перша реєстрація ключа пристрою ─────────────────────────────
// Повертає { publicKeyPem, environment } або кидає Error з причиною.
function verifyAttestation({ attestationB64, keyIdB64, challengeBytes }) {
  if (!configured()) throw new Error('App Attest не сконфігуровано (TEAM_ID/BUNDLE_ID/Root CA)');

  const att = cbor.decodeFirstSync(strictBase64(attestationB64, 256 * 1024));
  if (att.fmt !== 'apple-appattest') throw new Error(`Невірний fmt: ${att.fmt}`);

  const x5c = att.attStmt && att.attStmt.x5c;
  if (!Array.isArray(x5c) || x5c.length < 2) throw new Error('x5c chain відсутній');

  const credCert = new crypto.X509Certificate(x5c[0]);
  const caCert   = new crypto.X509Certificate(x5c[1]);

  // Ланцюг довіри: credCert ← caCert ← Apple Root.
  if (credCert.ca || !caCert.ca) throw new Error('Некоректні CA constraints');
  if (!credCert.verify(caCert.publicKey)) throw new Error('credCert не підписано caCert');
  if (!caCert.verify(ROOT_CA.publicKey))  throw new Error('caCert не підписано Apple Root CA');
  const now = new Date();
  if (now < new Date(credCert.validFrom) || now > new Date(credCert.validTo)) {
    throw new Error('credCert прострочений');
  }
  if (now < new Date(caCert.validFrom) || now > new Date(caCert.validTo)) {
    throw new Error('caCert прострочений');
  }

  const authData = att.authData;
  const clientDataHash = sha256(challengeBytes);
  const expectedNonce  = sha256(Buffer.concat([authData, clientDataHash]));

  const certNonce = extractCertNonce(x5c[0]);
  if (!certNonce || !crypto.timingSafeEqual(certNonce, expectedNonce)) {
    throw new Error('Nonce у сертифікаті не збігається (челендж підмінено?)');
  }

  // keyId == SHA256(нестиснута EC-точка публічного ключа credCert)
  const spki   = credCert.publicKey.export({ type: 'spki', format: 'der' });
  const keyId  = strictBase64(keyIdB64, 32);
  if (keyId.length !== 32) throw new Error('keyId має бути 32 байти');
  const calcId = sha256(ecPointFromSpki(spki));
  if (!crypto.timingSafeEqual(keyId, calcId)) throw new Error('keyId не відповідає ключу');

  const ad = parseAuthData(authData);
  if (!crypto.timingSafeEqual(ad.rpIdHash, sha256(Buffer.from(APP_ID)))) {
    throw new Error(`rpIdHash не збігається з App ID ${APP_ID}`);
  }
  if (ad.counter !== 0) throw new Error('counter attestation має бути 0');

  let environment;
  if (ad.aaguid && ad.aaguid.equals(AAGUID_PROD))     environment = 'production';
  else if (ad.aaguid && ad.aaguid.equals(AAGUID_DEV)) environment = 'development';
  else throw new Error('Невідомий aaguid');
  if (ATT_ENV === 'production' && environment !== 'production') {
    throw new Error('Development-атестація у прод-режимі');
  }

  if (!ad.credId || !crypto.timingSafeEqual(ad.credId, keyId)) {
    throw new Error('credentialId != keyId');
  }

  return {
    publicKeyPem: credCert.publicKey.export({ type: 'spki', format: 'pem' }),
    environment,
  };
}

// ── ASSERTION: підпис кожного аппруву зареєстрованим ключем ──────────────────
// Повертає новий counter або кидає Error.
// bodyBytes — ДОСЛІВНІ байти тіла запиту (canonical payload клієнта).
// Assertion привʼязаний до SHA256(challenge ‖ body): підмінити результати
// перевірок після підпису неможливо (аудит P0-05).
function verifyAssertion({ assertionB64, publicKeyPem, challengeBytes, bodyBytes, storedCounter }) {
  const asrt = cbor.decodeFirstSync(strictBase64(assertionB64, 64 * 1024));
  const { signature, authenticatorData } = asrt;
  if (!signature || !authenticatorData) throw new Error('Некоректна assertion');

  // Тіло ОБОВʼЯЗКОВЕ: жодного «якщо тіла немає — перевіримо лише
  // challenge» (це був би downgrade-вектор).
  if (!bodyBytes || !bodyBytes.length) throw new Error('Порожнє тіло для assertion');
  const clientDataHash = sha256(Buffer.concat([challengeBytes, bodyBytes]));
  const nonce = sha256(Buffer.concat([authenticatorData, clientDataHash]));

  const ok = crypto.createVerify('SHA256').update(nonce).verify(publicKeyPem, signature);
  if (!ok) throw new Error('Підпис assertion невалідний');

  const ad = parseAuthData(authenticatorData);
  if (!crypto.timingSafeEqual(ad.rpIdHash, sha256(Buffer.from(APP_ID)))) {
    throw new Error('rpIdHash assertion не збігається');
  }
  if (ad.counter <= storedCounter) {
    throw new Error(`Replay: counter ${ad.counter} <= ${storedCounter}`);
  }
  return ad.counter;
}

module.exports = {
  configured,
  issueChallenge,
  inspectChallenge,
  consumeChallenge,
  verifyAttestation,
  verifyAssertion,
};
