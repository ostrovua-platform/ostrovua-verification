'use strict';

const crypto = require('crypto');

const PASSWORD_HASH_PREFIX = 'ovua$bcrypt-sha512$v1$';
const COMMON_PASSWORDS = new Set([
  '123456789012345',
  'passwordpassword',
  'qwertyuiopasdfgh',
  'iloveyouiloveyou',
  'ostrovuaostrovua',
]);

function normalizedOrigin(value, { production = false } = {}) {
  let parsed;
  try {
    parsed = new URL(String(value || ''));
  } catch {
    throw new Error('PUBLIC_APP_URL must be an absolute http(s) URL');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('PUBLIC_APP_URL must use http or https');
  }
  const local = ['localhost', '127.0.0.1', '::1'].includes(parsed.hostname);
  if (production && parsed.protocol !== 'https:') {
    throw new Error('PUBLIC_APP_URL must use https in production');
  }
  if (!production && parsed.protocol === 'http:' && !local) {
    throw new Error('Insecure PUBLIC_APP_URL is allowed only for local development');
  }
  return parsed.origin;
}

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[char]);
}

function serializeForInlineScript(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function passwordPrehash(password) {
  return crypto.createHash('sha512').update(String(password), 'utf8').digest('base64');
}

function validateNewPassword(password, context = {}) {
  if (typeof password !== 'string') {
    return { ok: false, error: 'Пароль має бути текстом' };
  }

  const normalized = password.normalize('NFC');
  const characters = Array.from(normalized).length;
  if (characters < 15) {
    return { ok: false, error: 'Пароль має містити щонайменше 15 символів' };
  }
  if (characters > 128 || Buffer.byteLength(normalized, 'utf8') > 512) {
    return { ok: false, error: 'Пароль надто довгий' };
  }
  if (/[\u0000-\u001f\u007f]/u.test(normalized)) {
    return { ok: false, error: 'Пароль містить недопустимі керівні символи' };
  }

  const folded = normalized.toLocaleLowerCase('en-US');
  if (COMMON_PASSWORDS.has(folded)) {
    return { ok: false, error: 'Цей пароль надто поширений' };
  }

  const foldedCompact = folded.replace(/[^a-z0-9а-яіїєґ]/giu, '');
  const contextualValues = [
    context.name,
    context.email,
    String(context.email || '').split('@')[0],
  ];
  for (const candidate of contextualValues) {
    const token = String(candidate || '')
      .normalize('NFC')
      .toLocaleLowerCase('en-US')
      .replace(/[^a-z0-9а-яіїєґ]/giu, '');
    if (token.length >= 5 && foldedCompact.includes(token)) {
      return { ok: false, error: 'Пароль не повинен містити імʼя або email' };
    }
  }

  return { ok: true, normalized };
}

async function hashPassword(password, bcrypt, rounds) {
  const normalized = String(password).normalize('NFC');
  const hash = await bcrypt.hash(passwordPrehash(normalized), rounds);
  return `${PASSWORD_HASH_PREFIX}${hash}`;
}

async function verifyPassword(password, storedHash, bcrypt) {
  if (typeof storedHash !== 'string' || !storedHash) return false;
  if (storedHash.startsWith(PASSWORD_HASH_PREFIX)) {
    return bcrypt.compare(
      passwordPrehash(String(password).normalize('NFC')),
      storedHash.slice(PASSWORD_HASH_PREFIX.length)
    );
  }
  // Legacy bcrypt hashes are accepted only for login. New and changed
  // passwords always use the pre-hashed, versioned format above.
  return bcrypt.compare(String(password), storedHash);
}

function decodeBase64Strict(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) {
    return null;
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return null;
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) return null;
  return decoded;
}

function startsWith(buffer, signature) {
  return buffer.length >= signature.length &&
    signature.every((byte, index) => buffer[index] === byte);
}

function isoBrand(buffer) {
  if (buffer.length < 12 || buffer.toString('ascii', 4, 8) !== 'ftyp') return '';
  return buffer.toString('ascii', 8, 12);
}

function classifyUpload(buffer) {
  if (!Buffer.isBuffer(buffer)) return null;
  if (startsWith(buffer, [0xff, 0xd8, 0xff])) {
    return { extension: 'jpg', mime: 'image/jpeg', disposition: 'inline' };
  }
  if (startsWith(buffer, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    return { extension: 'png', mime: 'image/png', disposition: 'inline' };
  }
  if (buffer.length >= 6 && ['GIF87a', 'GIF89a'].includes(buffer.toString('ascii', 0, 6))) {
    return { extension: 'gif', mime: 'image/gif', disposition: 'inline' };
  }
  if (buffer.length >= 12 &&
      buffer.toString('ascii', 0, 4) === 'RIFF' &&
      buffer.toString('ascii', 8, 12) === 'WEBP') {
    return { extension: 'webp', mime: 'image/webp', disposition: 'inline' };
  }
  if (startsWith(buffer, [0x1a, 0x45, 0xdf, 0xa3])) {
    return { extension: 'webm', mime: 'video/webm', disposition: 'inline' };
  }

  const brand = isoBrand(buffer);
  if (['heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1'].includes(brand)) {
    return { extension: 'heic', mime: 'image/heic', disposition: 'inline' };
  }
  if (['avif', 'avis'].includes(brand)) {
    return { extension: 'avif', mime: 'image/avif', disposition: 'inline' };
  }
  if (['M4A ', 'M4B ', 'M4P '].includes(brand)) {
    return { extension: 'm4a', mime: 'audio/mp4', disposition: 'inline' };
  }
  if (brand === 'qt  ') {
    return { extension: 'mov', mime: 'video/quicktime', disposition: 'inline' };
  }
  if (brand && /^[A-Za-z0-9 ]{4}$/.test(brand)) {
    return { extension: 'mp4', mime: 'video/mp4', disposition: 'inline' };
  }
  if (buffer.length >= 5 && buffer.toString('ascii', 0, 5) === '%PDF-') {
    return { extension: 'pdf', mime: 'application/pdf', disposition: 'attachment' };
  }
  return null;
}

module.exports = {
  PASSWORD_HASH_PREFIX,
  classifyUpload,
  decodeBase64Strict,
  escapeHtml,
  hashPassword,
  normalizedOrigin,
  passwordPrehash,
  serializeForInlineScript,
  validateNewPassword,
  verifyPassword,
};
