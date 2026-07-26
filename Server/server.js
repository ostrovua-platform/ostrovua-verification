/**
 * OstrovUA Auth Microservice
 * Supports: email/password (bcrypt), Google OAuth, GitHub OAuth, Telegram Login Widget
 *
 * Routes:
 *   POST /auth/login              { email, password } → { token, contributor }
 *   POST /auth/register           { name, role, email, password } → { token, contributor }
 *   GET  /auth/google             → redirect to Google
 *   GET  /auth/google/callback    → JWT popup close
 *   GET  /auth/github             → redirect to GitHub
 *   GET  /auth/github/callback    → JWT popup close
 *   POST /auth/telegram           { id, first_name, hash, ... } → { token, contributor }
 *   GET  /auth/health             → { ok: true }
 */

'use strict';

const express        = require('express');
const passport       = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const bcrypt         = require('bcrypt');
const jwt            = require('jsonwebtoken');
const cors           = require('cors');
const fetch          = require('node-fetch');
const crypto         = require('crypto');
const fs             = require('fs');
const path           = require('path');
const {
  classifyUpload,
  decodeBase64Strict,
  escapeHtml,
  hashPassword,
  normalizeAvatarDataUrl,
  normalizedOrigin,
  serializeForInlineScript,
  validateNewPassword,
  verifyPassword,
} = require('./security_policy');
const { createAuthSecurityStore } = require('./auth_security_store');
const { createDocumentCA } = require('./document_ca');

const app = express();
const IS_PROD = (process.env.APP_ENV || process.env.NODE_ENV) === 'production';
// 40mb — щоб пройшли вкладення чату (25 МБ файл ≈ 34 МБ base64).
// Реальні межі тримає nginx: /auth/upload — 36m, решта /auth/ — 8m.
// rawBody — ДОСЛІВНІ байти тіла запиту: App Attest assertion підписує
// SHA256(challenge ‖ rawBody), тож перевіряти треба саме ті байти,
// що надіслав клієнт, а не пере-серіалізований JSON.
// DoS-межа (аудит P1-07): великий JSON-парсинг ЛИШЕ для /auth/upload;
// решта маршрутів — 512 КБ (verify/approve з SOD ~10 КБ вкладається
// з запасом). Раніше будь-який маршрут парсив до 40 МБ ще до JWT.
const captureRaw = (req, _res, buf) => { req.rawBody = buf; };
const bigJson   = express.json({ limit: '40mb',  verify: captureRaw });
const verifyJson = express.json({ limit: '12mb', verify: captureRaw });
const smallJson = express.json({ limit: '512kb', verify: captureRaw });
app.use((req, res, next) => {
  const parser = req.path === '/auth/upload'
    ? bigJson
    : (req.path === '/auth/verify/approve' ? verifyJson : smallJson);
  return parser(req, res, next);
});
app.use(express.urlencoded({ extended: true, limit: '512kb' }));

// ── CORS ─────────────────────────────────────────────────────────────────────
function parseAllowedOrigins(value) {
  const origins = new Set();
  for (const item of String(value || '').split(',')) {
    const raw = item.trim();
    if (!raw) continue;
    if (!IS_PROD && ['null', 'file://'].includes(raw)) {
      origins.add(raw);
      continue;
    }
    const canonical = normalizedOrigin(raw, { production: IS_PROD });
    if (canonical !== raw.replace(/\/+$/, '')) {
      throw new Error(`ALLOWED_ORIGINS contains a non-origin value: ${raw}`);
    }
    origins.add(canonical);
  }
  return origins;
}

let ALLOWED_ORIGINS;
try {
  ALLOWED_ORIGINS = parseAllowedOrigins(
    process.env.ALLOWED_ORIGINS ||
    (IS_PROD ? '' : 'http://localhost:5500,http://127.0.0.1:5500,null,file://')
  );
} catch (error) {
  console.error('[FATAL] ALLOWED_ORIGINS is invalid:', error.message);
  process.exit(1);
}

app.use(cors({
  origin: (origin, cb) => {
    // Requests from native clients have no Origin. Browser origins must match
    // the canonical allowlist exactly; production never permits null/file.
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    cb(new Error('CORS: origin not allowed'));
  },
  methods: ['GET', 'POST', 'DELETE'],
}));

// ── FILE-BACKED SECRETS ──────────────────────────────────────────────────────
// Production secrets must not be passed through the container environment:
// `docker inspect` exposes environment variables to Docker administrators and
// they are too easy to duplicate in .env/rollback files. Read the document
// token peppers once at startup from read-only files mounted under
// /run/secrets. The raw values are never logged.
function loadFileBackedSecret(name, { required = false, minBytes = 32 } = {}) {
  const inlineValue = process.env[name] || '';
  const fileName = process.env[`${name}_FILE`] || '';

  if (inlineValue && fileName) {
    throw new Error(`${name}: configure either ${name} or ${name}_FILE, not both`);
  }
  if (IS_PROD && inlineValue) {
    throw new Error(`${name}: inline environment secrets are forbidden in production`);
  }

  let value = inlineValue;
  if (fileName) {
    try {
      value = fs.readFileSync(fileName, 'utf8').trim();
    } catch {
      throw new Error(`${name}: unable to read configured secret file`);
    }
  }

  if (!value) {
    if (required) throw new Error(`${name}: secret is required`);
    return '';
  }
  if (Buffer.byteLength(value, 'utf8') < minBytes) {
    throw new Error(`${name}: secret must contain at least ${minBytes} bytes`);
  }
  return value;
}

let DOC_TOKEN_PEPPER = '';
let LEGACY_DOC_PEPPER = '';
let AUTH_RATE_LIMIT_PEPPER = '';
let AUTH_SESSION_METADATA_PEPPER = '';
let PASSWORD_RESET_PEPPER = '';
let DOCUMENT_CA_SEALING_KEY = null;
try {
  DOC_TOKEN_PEPPER = loadFileBackedSecret('DOC_TOKEN_PEPPER', {
    required: IS_PROD,
    minBytes: 32,
  });
  LEGACY_DOC_PEPPER = loadFileBackedSecret('DOC_TOKEN_PEPPER_PREVIOUS', {
    required: false,
    minBytes: 32,
  });
  if (LEGACY_DOC_PEPPER && LEGACY_DOC_PEPPER === DOC_TOKEN_PEPPER) {
    throw new Error('DOC_TOKEN_PEPPER_PREVIOUS must differ from DOC_TOKEN_PEPPER');
  }
  AUTH_RATE_LIMIT_PEPPER = loadFileBackedSecret('AUTH_RATE_LIMIT_PEPPER', {
    required: IS_PROD,
    minBytes: 32,
  });
  AUTH_SESSION_METADATA_PEPPER = loadFileBackedSecret('AUTH_SESSION_METADATA_PEPPER', {
    required: IS_PROD,
    minBytes: 32,
  });
  PASSWORD_RESET_PEPPER = loadFileBackedSecret('PASSWORD_RESET_PEPPER', {
    required: IS_PROD,
    minBytes: 32,
  });

  if (process.env.DOCUMENT_CA_SEALING_KEY) {
    throw new Error('DOCUMENT_CA_SEALING_KEY: inline secrets are forbidden');
  }
  const documentCAKeyFile = process.env.DOCUMENT_CA_SEALING_KEY_FILE || '';
  if (documentCAKeyFile) {
    try {
      DOCUMENT_CA_SEALING_KEY = fs.readFileSync(documentCAKeyFile);
    } catch {
      throw new Error('DOCUMENT_CA_SEALING_KEY_FILE: unable to read configured secret file');
    }
    if (DOCUMENT_CA_SEALING_KEY.length !== 32) {
      DOCUMENT_CA_SEALING_KEY.fill(0);
      DOCUMENT_CA_SEALING_KEY = null;
      throw new Error('DOCUMENT_CA_SEALING_KEY_FILE: key must be exactly 32 bytes');
    }
  }
  if (process.env.SERVER_OWNED_CA_ENABLED === '1' && !DOCUMENT_CA_SEALING_KEY) {
    throw new Error('SERVER_OWNED_CA_ENABLED requires DOCUMENT_CA_SEALING_KEY_FILE');
  }
} catch (error) {
  console.error('[FATAL] File-backed secret configuration is invalid:', error.message);
  process.exit(1);
}

if (IS_PROD) app.set('trust proxy', 1);   // за nginx: secure-cookie + правильний X-Forwarded-*
app.use(passport.initialize());

// ── CONFIG ────────────────────────────────────────────────────────────────────
const HASURA_URL       = process.env.HASURA_URL           || 'http://hasura:8080/v1/graphql';
const ADMIN_SECRET     = process.env.HASURA_ADMIN_SECRET  || '';
const JWT_SECRET       = process.env.JWT_SECRET           || '';
const JWT_EXPIRES      = process.env.JWT_EXPIRES          || '7d';
const BCRYPT_ROUNDS    = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const PORT             = parseInt(process.env.PORT || '3001', 10);
const AUTH_BASE_URL    = process.env.AUTH_BASE_URL        || `http://localhost:${PORT}`;
const AUTH_SESSION_ENFORCEMENT_ENABLED =
  process.env.AUTH_SESSION_ENFORCEMENT_ENABLED === '1';

// ── FAIL-FAST: не стартуємо в проді з дефолтними/слабкими секретами ──────────────
if (IS_PROD) {
  const bad = [];
  if (!JWT_SECRET) bad.push('JWT_SECRET');
  if (JWT_SECRET.length < 32) bad.push('JWT_SECRET (min 32 chars)');
  if (!ADMIN_SECRET) bad.push('HASURA_ADMIN_SECRET');
  if (!process.env.ALLOWED_ORIGINS) bad.push('ALLOWED_ORIGINS');
  if (process.env.VERIFY_DEV_BYPASS === '1') bad.push('VERIFY_DEV_BYPASS must NOT be set in prod');
  if (bad.length) {
    console.error('[FATAL] Небезпечна прод-конфігурація, старт скасовано:', bad.join(', '));
    process.exit(1);
  }
}

const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GITHUB_CLIENT_ID     = process.env.GITHUB_CLIENT_ID     || '';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';
const TELEGRAM_BOT_TOKEN   = process.env.TELEGRAM_BOT_TOKEN   || '';
const TELEGRAM_BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || '';
const RESEND_API_KEY       = process.env.RESEND_API_KEY      || '';
const RESEND_FROM          = process.env.RESEND_FROM         || 'OstrovUA <onboarding@resend.dev>';
const PUBLIC_APP_URL       = (process.env.PUBLIC_APP_URL     || 'http://localhost:5500').replace(/\/+$/, '');
const INVITE_TTL_DAYS      = parseInt(process.env.INVITE_TTL_DAYS || '7', 10);
let OAUTH_TARGET_ORIGIN;
try {
  OAUTH_TARGET_ORIGIN = normalizedOrigin(PUBLIC_APP_URL, { production: IS_PROD });
} catch (error) {
  console.error('[FATAL] PUBLIC_APP_URL is invalid:', error.message);
  process.exit(1);
}
if (IS_PROD && !ALLOWED_ORIGINS.has(OAUTH_TARGET_ORIGIN)) {
  console.error('[FATAL] PUBLIC_APP_URL origin must be present in ALLOWED_ORIGINS');
  process.exit(1);
}

// ── HASURA ADMIN QUERY ───────────────────────────────────────────────────────
async function hasuraAdmin(query, variables = {}) {
  const res = await fetch(HASURA_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'x-hasura-admin-secret': ADMIN_SECRET },
    body:    JSON.stringify({ query, variables }),
  });
  if (!res.ok) throw new Error(`Hasura HTTP ${res.status}`);
  const json = await res.json();
  if (json.errors) throw new Error(json.errors[0].message);
  return json.data;
}

// Прямий SQL через Hasura /v2/query (run_sql) — щоб викликати plpgsql-
// функцію verify_bind_document БЕЗ залежності від GraphQL-трекінгу
// (Hasura не завжди виставляє скалярні функції в mutation_root).
// Повертає масив рядків результату (без рядка заголовків).
const HASURA_SQL_URL = HASURA_URL.replace('/v1/graphql', '/v2/query');
async function hasuraSQL(sql) {
  const res = await fetch(HASURA_SQL_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'x-hasura-admin-secret': ADMIN_SECRET },
    body:    JSON.stringify({ type: 'run_sql', args: { source: 'default', sql, read_only: false } }),
  });
  const json = await res.json();
  if (!res.ok || json.error) throw new Error(json.error || `Hasura run_sql HTTP ${res.status}`);
  const rows = json.result || [];
  return rows.slice(1);   // [0] — заголовки колонок
}

const authSecurityStore = createAuthSecurityStore(hasuraSQL, {
  rateLimitPepper: AUTH_RATE_LIMIT_PEPPER,
  metadataPepper: AUTH_SESSION_METADATA_PEPPER,
});

// ── ЛІМІТ СПРОБ LIVENESS (анти-реплей перебору) ───────────────────────
// Кожна спроба бере свіжий challenge → рахуємо видачі на ключ
// (акаунт+пристрій), ескалація кулдаунів (5→1г, 7→1д, 10→1тиж, далі —
// жорсткий лок з апеляцією). Логіка атомарна у plpgsql rl_touch.
// БЕЗПЕКА: ключ суворо валідований ДО SQL — інʼєкція неможлива.
function rlKeyValid(key) {
  return /^acct:[0-9a-fA-F-]{36}$/.test(key) ||
    /^dev:[A-Za-z0-9+/=_-]{1,64}$/.test(key);
}
async function rlQuery(functionName, key) {
  if (!rlKeyValid(key)) throw new Error('verification_rate_limit_key_invalid');
  return verificationStore.rateLimit(functionName, key);
}
const rlTouch = (key) => rlQuery('rl_touch', key);
const rlCheck = (key) => rlQuery('rl_check', key);
async function rlReset(key) {
  if (!rlKeyValid(key)) throw new Error('verification_rate_limit_key_invalid');
  await verificationStore.resetRateLimit(key);
}
function rlKeysFor(contributorId, req) {
  const keys = [];
  if (/^[0-9a-fA-F-]{36}$/.test(contributorId || '')) {
    keys.push(`acct:${contributorId}`);
  }
  const device = req.headers['x-attest-key'];
  if (typeof device === 'string' && /^[A-Za-z0-9+/=_-]{1,64}$/.test(device)) {
    keys.push(`dev:${device}`);
  }
  if (keys.length !== 2) {
    throw new Error('verification_rate_limit_identity_incomplete');
  }
  return keys;
}
function rlLockedMessage(until) {
  const milliseconds = until ? new Date(until).getTime() - Date.now() : 0;
  if (milliseconds > 300 * 24 * 3600e3) {
    return 'Верифікацію заблоковано за підозрілу активність. Звернись у підтримку (апеляція).';
  }
  const hours = Math.ceil(milliseconds / 3600e3);
  const when = hours >= 24
    ? `${Math.ceil(hours / 24)} дн.`
    : `${Math.max(1, hours)} год.`;
  return `Забагато спроб верифікації. Спробуй за ${when}.`;
}

// ── FIND OR CREATE CONTRIBUTOR (for OAuth) ────────────────────────────────────
async function findOrCreateContributor({ email, name, photo_url, provider, provider_id }) {
  // 1. Try find by OAuth provider ID — most reliable, works even without email
  if (provider && provider_id) {
    const found = await hasuraAdmin(
      `query($pid: String!, $prov: String!) {
         contributors(where:{oauth_provider_id:{_eq:$pid}, oauth_provider:{_eq:$prov}}, limit:1)
         { id name role photo_url consent_level password_hash }
       }`,
      { pid: String(provider_id), prov: provider }
    );
    if (found.contributors?.[0]) return withTheme(found.contributors[0]);
  }

  // 2. Try find by email (e.g. user registered via email/password earlier)
  if (email) {
    const found = await hasuraAdmin(
      `query($email: String!) {
         contributors(where:{email:{_eq:$email}}, limit:1)
         { id name role photo_url consent_level password_hash }
       }`,
      { email }
    );
    if (found.contributors?.[0]) {
      const existing = found.contributors[0];
      // Link OAuth provider to this account so next login uses provider_id lookup
      if (provider && provider_id && !existing.oauth_provider_id) {
        await hasuraAdmin(
          `mutation($id: uuid!, $pid: String!, $prov: String!) {
             update_contributors_by_pk(pk_columns:{id:$id}, _set:{oauth_provider_id:$pid, oauth_provider:$prov})
             { id }
           }`,
          { id: existing.id, pid: String(provider_id), prov: provider }
        ).catch(() => {}); // non-fatal
      }
      return withTheme(existing);
    }
  }

  // 3. Create new contributor
  const inserted = await hasuraAdmin(
    `mutation($obj: contributors_insert_input!) {
       insert_contributors_one(object:$obj) { id name role photo_url consent_level password_hash }
     }`,
    { obj: {
        name:              name || 'OAuth User',
        email:             email || null,
        role:              'Учасник',
        status:            'active',
        description:       '',
        consent_level:     'none',
        photo_url:         photo_url || null,
        oauth_provider:    provider    || null,
        oauth_provider_id: provider_id ? String(provider_id) : null,
    }}
  );
  return withTheme(inserted.insert_contributors_one);
}

// ── JWT HELPER ────────────────────────────────────────────────────────────────
async function issueToken(contributor, req) {
  const sessionId = crypto.randomUUID();
  const token = jwt.sign(
    {
      'https://hasura.io/jwt/claims': {
        'x-hasura-default-role':   'user',
        'x-hasura-allowed-roles':  ['user'],
        'x-hasura-contributor-id': contributor.id,
      },
      sub: contributor.id,
      name: contributor.name,
      role: contributor.role,
      sid: sessionId,
      jti: crypto.randomUUID(),
      auth_time: Math.floor(Date.now() / 1000),
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
  const claims = jwt.decode(token);
  if (!claims?.exp) throw new Error('auth_session_token_expiry_missing');
  await authSecurityStore.createSession({
    sessionId,
    contributorId: contributor.id,
    expiresAt: new Date(claims.exp * 1000),
    ip: req?.ip || '',
    userAgent: req?.get?.('user-agent') || '',
  });
  return token;
}

function safe(c) { const { password_hash, ...rest } = c; return rest; }

// Best-effort збагачення контриб'ютора темою. Не валить запит, якщо колонки
// theme ще немає в БД (міграція не застосована) — тоді просто 'dark'.
// Так порядок застосування міграцій не ламає вхід/реєстрацію.
async function withTheme(c) {
  if (!c) return c;
  try {
    const d = await hasuraAdmin(
      `query($id: uuid!) { contributors_by_pk(id:$id) { theme } }`, { id: c.id }
    );
    c.theme = d.contributors_by_pk?.theme || 'dark';
  } catch (_) {
    c.theme = 'dark';
  }
  return c;
}

// ── OAUTH CALLBACK PAGE (closes popup, sends JWT to opener) ───────────────────
function oauthSuccessPage(token, contributor) {
  const nonce = crypto.randomBytes(18).toString('base64');
  const data = serializeForInlineScript({ token, contributor: safe(contributor) });
  const target = serializeForInlineScript(OAUTH_TARGET_ORIGIN);
  return `<!DOCTYPE html><html><head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-${nonce}'; style-src 'none'; base-uri 'none'; form-action 'none'">
    <meta name="referrer" content="no-referrer">
  </head><body><script nonce="${nonce}">
    try {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage(${data}, ${target});
      }
    } catch(e) {}
    window.close();
  </script><p>Авторизація успішна. Закрий це вікно.</p></body></html>`;
}

function oauthErrorPage(msg) {
  const nonce = crypto.randomBytes(18).toString('base64');
  const payload = serializeForInlineScript({ error: String(msg || 'OAuth failed') });
  const target = serializeForInlineScript(OAUTH_TARGET_ORIGIN);
  return `<!DOCTYPE html><html><head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-${nonce}'; style-src 'none'; base-uri 'none'; form-action 'none'">
    <meta name="referrer" content="no-referrer">
  </head><body><script nonce="${nonce}">
    try {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage(${payload}, ${target});
      }
    } catch(e) {}
    window.close();
  </script><p>Помилка: ${escapeHtml(msg)}</p></body></html>`;
}

// ── INVITE: перевірка координатора ──────────────────────────────────────────────
// Запрошувати може лише координатор (contributors.is_coordinator = true).
async function isCoordinator(contributorId) {
  if (!contributorId) return false;
  try {
    const data = await hasuraAdmin(
      `query($id: uuid!) { contributors_by_pk(id:$id) { is_coordinator } }`,
      { id: contributorId }
    );
    return !!data.contributors_by_pk?.is_coordinator;
  } catch (e) {
    console.error('[isCoordinator]', e.message);
    return false;
  }
}

// ── INVITE: HTML-лист у фірмовому стилі OstrovUA ────────────────────────────────
function esc(s) {
  return String(s || '').replace(/[&<>"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;' }[c]));
}
function inviteEmailHTML({ name, role, link }) {
  const safeName = esc(name) || 'друже';
  const safeRole = esc(role);
  // Інлайн-стилі (поштові клієнти не тягнуть <style>/зовнішній CSS). Темна тема бренду.
  return `<!DOCTYPE html>
<html lang="uk"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Запрошення до OstrovUA</title></head>
<body style="margin:0;padding:0;background:#080a18;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#080a18;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#0c0f22;border:1px solid #1e2240;border-radius:20px;overflow:hidden;">
        <!-- Шапка -->
        <tr><td style="padding:36px 32px 8px;text-align:center;background:radial-gradient(ellipse 90% 70% at 50% 0%, rgba(200,224,58,.10) 0%, transparent 70%);">
          <div style="display:inline-block;border:2px solid #c8e03a;border-radius:16px;padding:12px 18px;background:rgba(200,224,58,.07);">
            <span style="font-size:22px;font-weight:800;color:#eef0fa;letter-spacing:.5px;">Ostrov<span style="color:#c8e03a;">UA</span></span>
          </div>
        </td></tr>
        <!-- Тіло -->
        <tr><td style="padding:20px 36px 8px;">
          <h1 style="margin:0 0 14px;font-size:21px;line-height:1.3;color:#eef0fa;font-weight:800;">Вітаємо, ${safeName}! 👋</h1>
          <p style="margin:0 0 16px;font-size:15px;line-height:1.65;color:#aeb4cc;">
            Тебе запрошено приєднатися до спільноти <strong style="color:#eef0fa;">OstrovUA</strong>${safeRole ? ` як <strong style="color:#c8e03a;">${safeRole}</strong>` : ''}.
          </p>
          <p style="margin:0 0 26px;font-size:15px;line-height:1.65;color:#aeb4cc;">
            Натисни кнопку нижче, придумай пароль — і можеш одразу почати користуватися базою.
          </p>
          <!-- CTA -->
          <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto 26px;"><tr>
            <td align="center" style="border-radius:10px;background:#c8e03a;">
              <a href="${link}" target="_blank"
                 style="display:inline-block;padding:14px 34px;font-size:15px;font-weight:800;color:#0c0f22;text-decoration:none;letter-spacing:.3px;">
                Створити пароль →
              </a>
            </td>
          </tr></table>
          <p style="margin:0 0 6px;font-size:12px;line-height:1.6;color:#6b7494;">
            Або скопіюй це посилання у браузер:
          </p>
          <p style="margin:0 0 22px;font-size:12px;line-height:1.6;word-break:break-all;">
            <a href="${link}" target="_blank" style="color:#c8e03a;text-decoration:none;">${link}</a>
          </p>
          <div style="border-top:1px solid #1e2240;margin:0 0 18px;"></div>
          <p style="margin:0;font-size:12px;line-height:1.6;color:#6b7494;">
            Посилання діє ${INVITE_TTL_DAYS} ${INVITE_TTL_DAYS === 1 ? 'день' : 'днів'} і відкриється лише один раз.
            Якщо ти не очікував(ла) цього листа — просто проігноруй його.
          </p>
        </td></tr>
        <!-- Підвал -->
        <tr><td style="padding:18px 36px 30px;text-align:center;">
          <p style="margin:0;font-size:11px;color:#4a5170;">© OstrovUA · спільнота учасників</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

// ── INVITE: відправка через Resend API ──────────────────────────────────────────
async function sendInviteEmail({ to, name, role, link }) {
  if (!RESEND_API_KEY) {
    throw new Error('RESEND_API_KEY не налаштовано');
  }
  const res = await fetch('https://api.resend.com/emails', {
    method:  'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type':  'application/json',
    },
    body: JSON.stringify({
      from:    RESEND_FROM,
      to:      [to],
      subject: 'Запрошення до OstrovUA',
      html:    inviteEmailHTML({ name, role, link }),
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Resend ${res.status}: ${body.slice(0, 300)}`);
  }
  return res.json();
}

// ── DISTRIBUTED RATE LIMITING ─────────────────────────────────────────────────
// PostgreSQL owns the counter and row lock, so adding auth replicas cannot
// reset or split the limit. Any store failure is fail-closed.
function routeRatePolicy(req) {
  const strict = new Set([
    '/auth/login',
    '/auth/register',
    '/auth/accept-invite',
    '/auth/forgot-password',
    '/auth/reset-password',
    '/auth/telegram',
  ]);
  if (strict.has(req.path)) {
    return { limit: 10, windowSeconds: 300, blockSeconds: 900 };
  }
  if (req.path === '/auth/upload') {
    return { limit: 20, windowSeconds: 60, blockSeconds: 300 };
  }
  return { limit: 120, windowSeconds: 60, blockSeconds: 300 };
}

function rateBucket(req) {
  const suffix = String(req.path || '/unknown')
    .toLowerCase()
    .replace(/^\/+/, '')
    .replace(/[^a-z0-9/_-]/g, '_')
    .replace(/\//g, ':')
    .slice(0, 48);
  return `route:${suffix || 'unknown'}`;
}

async function consumeAuthRateLimit({ bucket, identity, ...policy }) {
  return authSecurityStore.consumeRateLimit({ bucket, identity, ...policy });
}

async function rateLimit(req, res, next) {
  try {
    const result = await consumeAuthRateLimit({
      bucket: rateBucket(req),
      identity: `ip:${req.ip || 'unknown'}`,
      ...routeRatePolicy(req),
    });
    if (!result.allowed) {
      res.set('Retry-After', String(result.retryAfterSeconds));
      return res.status(429).json({ error: 'Занадто багато спроб.' });
    }
    return next();
  } catch (error) {
    console.error('[auth-rate-limit]', error.message);
    return res.status(503).json({ error: 'Захист авторизації тимчасово недоступний' });
  }
}

async function enforceIdentityRateLimit(res, {
  bucket,
  identity,
  limit = 8,
  windowSeconds = 900,
  blockSeconds = 1800,
}) {
  try {
    const result = await consumeAuthRateLimit({
      bucket,
      identity,
      limit,
      windowSeconds,
      blockSeconds,
    });
    if (result.allowed) return true;
    res.set('Retry-After', String(result.retryAfterSeconds));
    res.status(429).json({ error: 'Занадто багато спроб.' });
    return false;
  } catch (error) {
    console.error('[auth-identity-rate-limit]', error.message);
    res.status(503).json({ error: 'Захист авторизації тимчасово недоступний' });
    return false;
  }
}

// ── STATELESS OAUTH STATE ─────────────────────────────────────────────────────
// The random state is kept only in a host-only HttpOnly cookie. This avoids
// process-local browser state, works across replicas and rejects login-CSRF.
const OAUTH_STATE_TTL_MS = 10 * 60_000;
function oauthStateCookie(provider) {
  return `${IS_PROD ? '__Host-' : ''}ovua_oauth_state_${provider}`;
}
function cookieValue(req, name) {
  const prefix = `${name}=`;
  for (const part of String(req.headers.cookie || '').split(';')) {
    const item = part.trim();
    if (!item.startsWith(prefix)) continue;
    try {
      return decodeURIComponent(item.slice(prefix.length));
    } catch {
      return '';
    }
  }
  return '';
}
function oauthCookieOptions() {
  return {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    path: '/',
    maxAge: OAUTH_STATE_TTL_MS,
  };
}
function startOAuth(provider, strategy, scope) {
  return (req, res, next) => {
    const state = crypto.randomBytes(32).toString('base64url');
    res.cookie(oauthStateCookie(provider), state, oauthCookieOptions());
    res.set('Cache-Control', 'no-store');
    return passport.authenticate(strategy, {
      scope,
      state,
      session: false,
    })(req, res, next);
  };
}
function verifyOAuthState(provider) {
  return (req, res, next) => {
    const cookieName = oauthStateCookie(provider);
    const expected = cookieValue(req, cookieName);
    const received = typeof req.query.state === 'string' ? req.query.state : '';
    res.clearCookie(cookieName, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: 'lax',
      path: '/',
    });
    res.set('Cache-Control', 'no-store');

    const wellFormed = /^[A-Za-z0-9_-]{43}$/.test(expected) &&
      /^[A-Za-z0-9_-]{43}$/.test(received);
    const equal = wellFormed && crypto.timingSafeEqual(
      Buffer.from(expected, 'ascii'),
      Buffer.from(received, 'ascii')
    );
    if (!equal) {
      return res.status(400).send(oauthErrorPage('OAuth state validation failed'));
    }
    return next();
  };
}

// ── GOOGLE OAUTH ──────────────────────────────────────────────────────────────
if (GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
    clientID:     GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL:  `${AUTH_BASE_URL}/auth/google/callback`,
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email    = profile.emails?.[0]?.value;
      const name     = profile.displayName;
      const photo    = profile.photos?.[0]?.value;
      const contrib  = await findOrCreateContributor({ email, name, photo_url: photo, provider: 'google', provider_id: profile.id });
      done(null, contrib);
    } catch (e) { done(e); }
  }));

  app.get('/auth/google', startOAuth('google', 'google', ['email', 'profile']));
  app.get('/auth/google/callback',
    verifyOAuthState('google'),
    passport.authenticate('google', { failureRedirect: '/auth/google/error', session: false }),
    async (req, res) => {
      try {
        const token = await issueToken(req.user, req);
        return res.send(oauthSuccessPage(token, req.user));
      } catch (error) {
        console.error('[google-session]', error.message);
        return res.status(503).send(oauthErrorPage('Session service unavailable'));
      }
    }
  );
  app.get('/auth/google/error', (_, res) => res.send(oauthErrorPage('Google auth failed')));
} else {
  app.get('/auth/google', (_, res) => res.send(oauthErrorPage('Google OAuth not configured')));
}

// ── GITHUB OAUTH ──────────────────────────────────────────────────────────────
if (GITHUB_CLIENT_ID) {
  passport.use(new GitHubStrategy({
    clientID:     GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL:  `${AUTH_BASE_URL}/auth/github/callback`,
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email   = profile.emails?.find(e => e.primary)?.value || profile.emails?.[0]?.value;
      const name    = profile.displayName || profile.username;
      const photo   = profile.photos?.[0]?.value;
      const contrib = await findOrCreateContributor({ email, name, photo_url: photo, provider: 'github', provider_id: profile.id });
      done(null, contrib);
    } catch (e) { done(e); }
  }));

  app.get('/auth/github', startOAuth('github', 'github', ['user:email']));
  app.get('/auth/github/callback',
    verifyOAuthState('github'),
    passport.authenticate('github', { failureRedirect: '/auth/github/error', session: false }),
    async (req, res) => {
      try {
        const token = await issueToken(req.user, req);
        return res.send(oauthSuccessPage(token, req.user));
      } catch (error) {
        console.error('[github-session]', error.message);
        return res.status(503).send(oauthErrorPage('Session service unavailable'));
      }
    }
  );
  app.get('/auth/github/error', (_, res) => res.send(oauthErrorPage('GitHub auth failed')));
} else {
  app.get('/auth/github', (_, res) => res.send(oauthErrorPage('GitHub OAuth not configured')));
}

// ── TELEGRAM WIDGET PAGE ──────────────────────────────────────────────────────
// Popup page with pre-rendered Telegram Login Widget
const TELEGRAM_BOT_USERNAME_CLEAN = (TELEGRAM_BOT_USERNAME || '').replace(/^@/, '');

app.get('/auth/telegram/widget', (req, res) => {
  if (!TELEGRAM_BOT_USERNAME_CLEAN) return res.send(oauthErrorPage('Telegram bot not configured'));
  const nonce = crypto.randomBytes(18).toString('base64');
  const targetOrigin = serializeForInlineScript(OAUTH_TARGET_ORIGIN);
  res.send(`<!DOCTYPE html>
<html lang="uk">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; script-src 'nonce-${nonce}' https://telegram.org; style-src 'nonce-${nonce}'; connect-src 'self'; frame-src https://oauth.telegram.org https://t.me; img-src https: data:; base-uri 'none'; form-action 'none'">
  <title>Вхід через Telegram</title>
  <style nonce="${nonce}">
    body { display:flex; align-items:center; justify-content:center; min-height:100vh;
           margin:0; font-family:system-ui,sans-serif; background:#f0f2f5; }
    .box { background:#fff; border-radius:12px; padding:32px 40px; text-align:center;
           box-shadow:0 2px 16px rgba(0,0,0,.1); }
    h2 { margin:0 0 24px; font-size:18px; color:#222; }
    #msg { margin-top:16px; color:#888; font-size:14px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Вхід через Telegram</h2>
    <script nonce="${nonce}" async src="https://telegram.org/js/telegram-widget.js?22"
      data-telegram-login="${escapeHtml(TELEGRAM_BOT_USERNAME_CLEAN)}"
      data-size="large"
      data-onauth="onTelegramAuth(user)"
      data-request-access="write">
    </script>
    <div id="msg">Натисніть кнопку вище, щоб увійти</div>
  </div>
  <script nonce="${nonce}">
    async function onTelegramAuth(user) {
      document.getElementById('msg').textContent = 'Перевірка…';
      try {
        const r = await fetch('/auth/telegram', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(user)
        });
        const data = await r.json();
        if (!r.ok) {
          document.getElementById('msg').textContent = 'Помилка: ' + (data.error || r.status);
          return;
        }
        if (window.opener) {
          window.opener.postMessage(data, ${targetOrigin});
          window.close();
        } else {
          document.getElementById('msg').textContent = 'Готово! Можна закрити вікно.';
        }
      } catch (e) {
        document.getElementById('msg').textContent = 'Помилка з\\'єднання';
      }
    }
  </script>
</body>
</html>`);
});

// ── TELEGRAM LOGIN WIDGET ─────────────────────────────────────────────────────
// Frontend sends the data object from Telegram widget's onAuth callback
app.post('/auth/telegram', rateLimit, async (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(503).json({ error: 'Telegram not configured' });

  const data = req.body;
  const { hash, ...checkData } = data;
  if (!hash) return res.status(400).json({ error: 'Missing hash' });

  // Verify hash per Telegram docs
  const dataCheckString = Object.keys(checkData)
    .sort()
    .map(k => `${k}=${checkData[k]}`)
    .join('\n');

  const secretKey = crypto.createHash('sha256').update(TELEGRAM_BOT_TOKEN).digest();
  const expectedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (expectedHash !== hash) return res.status(401).json({ error: 'Invalid Telegram signature' });

  // Check auth_date not too old (< 1 day)
  if (Date.now() / 1000 - parseInt(data.auth_date) > 86400) {
    return res.status(401).json({ error: 'Telegram auth expired' });
  }

  try {
    const name     = [data.first_name, data.last_name].filter(Boolean).join(' ');
    const email    = null; // Telegram doesn't provide email
    const photo    = data.photo_url || null;
    const contrib  = await findOrCreateContributor({ email, name, photo_url: photo, provider: 'telegram', provider_id: data.id });
    const token    = await issueToken(contrib, req);
    return res.json({ token, contributor: safe(contrib) });
  } catch (e) {
    console.error('[telegram]', e.message);
    return res.status(500).json({ error: 'Помилка входу через Telegram' });
  }
});

// ── EMAIL/PASSWORD ROUTES (unchanged) ─────────────────────────────────────────
app.get('/auth/health', (_, res) => res.json({ ok: true }));

app.post('/auth/login', rateLimit, async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  const password = req.body?.password;
  if (!email || !password) return res.status(400).json({ error: 'Невірний email або пароль' });
  if (!await enforceIdentityRateLimit(res, {
    bucket: 'login:email',
    identity: `email:${email}`,
    limit: 8,
  })) return;
  try {
    const data = await hasuraAdmin(
      `query Login($email: String!) {
         contributors(where:{email:{_eq:$email}}, limit:1) { id name role photo_url consent_level password_hash banned }
       }`, { email }
    );
    const c = data.contributors?.[0];
    const hashToCompare = c?.password_hash || '$2b$12$invalidhashfortimingattackprevention00000000000000000';
    const ok = await verifyPassword(password, hashToCompare, bcrypt);
    if (!c || !ok) return res.status(401).json({ error: 'Невірний email або пароль' });
    // Бан: пароль правильний, але вхід заборонено (перевіряємо ПІСЛЯ
    // пароля, щоб не розкривати стан акаунта стороннім).
    if (c.banned) return res.status(403).json({ error: 'Акаунт заблоковано за порушення правил спільноти.' });
    return res.json({
      token: await issueToken(c, req),
      contributor: safe(await withTheme(c)),
    });
  } catch (e) {
    console.error('[login]', e.message);
    return res.status(500).json({ error: 'Помилка входу. Спробуй пізніше.' });
  }
});

// Роль користувача НЕ довіряємо клієнту: будь-хто міг зареєструватися
// з role='Координатор'. Дозволені лише безпечні значення; реальні права
// дає окремий прапорець is_coordinator, який ставить лише адміністратор.
const ALLOWED_SELF_ROLES = ['Учасник', 'Участник', 'Member'];
const sanitizeRole = (role) =>
  ALLOWED_SELF_ROLES.includes((role || '').trim()) ? role.trim() : 'Учасник';

app.post('/auth/register', rateLimit, async (req, res) => {
  const { name, password } = req.body || {};
  const role = sanitizeRole(req.body?.role);
  const email = (req.body?.email || '').trim().toLowerCase();   // нормалізація
  if (!name || !role || !email || !password) return res.status(400).json({ error: 'Заповни всі поля' });
  const passwordPolicy = validateNewPassword(password, { email, name });
  if (!passwordPolicy.ok) return res.status(400).json({ error: passwordPolicy.error });
  if (!await enforceIdentityRateLimit(res, {
    bucket: 'register:email',
    identity: `email:${email}`,
    limit: 5,
    windowSeconds: 3600,
    blockSeconds: 3600,
  })) return;
  try {
    // INVITE-ONLY: реєстрація лише для заздалегідь доданих email.
    const inv = await hasuraAdmin(
      `query($e: String!) { invited_emails(where:{ email:{_eq:$e}, used:{_eq:false} }, limit:1) { email } }`,
      { e: email }
    );
    if (!inv.invited_emails?.length) {
      return res.status(403).json({ error: 'Цей email не запрошений. Звернись до координатора.' });
    }

    const check = await hasuraAdmin(
      `query($email: String!) { contributors(where:{email:{_eq:$email}}, limit:1) { id } }`, { email }
    );
    if (check.contributors?.length) return res.status(409).json({ error: 'Не вдалось зареєструватись. Спробуй інший email.' });

    const password_hash = await hashPassword(passwordPolicy.normalized, bcrypt, BCRYPT_ROUNDS);
    const insert = await hasuraAdmin(
      `mutation($obj: contributors_insert_input!) {
         insert_contributors_one(object:$obj) { id name role photo_url consent_level password_hash }
       }`,
      { obj: { name, role, email, password_hash, status: 'active', description: '', consent_level: 'none' } }
    );
    const c = insert.insert_contributors_one;

    // Гасимо інвайт (одноразовий).
    await hasuraAdmin(
      `mutation($e: String!, $at: timestamptz!) {
         update_invited_emails(where:{email:{_eq:$e}}, _set:{ used:true, used_at:$at }) { affected_rows }
       }`,
      { e: email, at: new Date().toISOString() }
    );

    return res.json({
      token: await issueToken(c, req),
      contributor: safe(await withTheme(c)),
    });
  } catch (e) {
    console.error('[register]', e.message);
    return res.status(500).json({ error: 'Помилка реєстрації. Спробуй пізніше.' });
  }
});

// ── CHANGE PASSWORD ───────────────────────────────────────────────────────────
app.post('/auth/change-password', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Вкажи старий та новий пароль' });
  const passwordPolicy = validateNewPassword(newPassword);
  if (!passwordPolicy.ok) return res.status(400).json({ error: passwordPolicy.error });

  try {
    const data = await hasuraAdmin(
      `query($id: uuid!) { contributors_by_pk(id:$id) { id name email role password_hash } }`,
      { id: contributorId }
    );
    const c = data.contributors_by_pk;
    if (!c) return res.status(404).json({ error: 'Учасника не знайдено' });
    if (!c.password_hash) return res.status(400).json({ error: 'Цей акаунт використовує OAuth (без пароля)' });

    const ok = await verifyPassword(oldPassword, c.password_hash, bcrypt);
    if (!ok) return res.status(401).json({ error: 'Невірний поточний пароль' });

    const contextualPolicy = validateNewPassword(newPassword, {
      email: c.email,
      name: c.name,
    });
    if (!contextualPolicy.ok) {
      return res.status(400).json({ error: contextualPolicy.error });
    }

    const newHash = await hashPassword(contextualPolicy.normalized, bcrypt, BCRYPT_ROUNDS);
    await authSecurityStore.changePassword({
      contributorId,
      currentPasswordHash: c.password_hash,
      passwordHash: newHash,
    });
    const token = await issueToken(c, req);
    return res.json({ ok: true, token });
  } catch(e) {
    console.error('[change-password]', e.message);
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});

// ── ВІДНОВЛЕННЯ ПАРОЛЯ ────────────────────────────────────────────────────────
// Пошта → 12-символьний код (діє 15 хв) → новий пароль.
//
// Захист:
//   • у базі лежить лише HMAC-SHA-256 від коду з окремим server-side pepper;
//   • максимум 5 спроб введення на код;
//   • відповідь на /forgot-password ЗАВЖДИ однакова, тож перебором
//     не дізнатися, чи є така пошта в системі;
//   • після зміни пароля всі невикористані коди цієї людини гинуть.
function resetEmailHTML({ name, code }) {
  return `<!doctype html><html><body style="margin:0;padding:24px;background:#0f1520;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#e8ecf1">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
    <table width="440" cellpadding="0" cellspacing="0" style="background:#151d2b;border-radius:16px;padding:28px">
      <tr><td style="font-size:20px;font-weight:700;padding-bottom:8px">Відновлення пароля</td></tr>
      <tr><td style="font-size:14px;color:#a9b4c2;padding-bottom:20px">
        ${name ? escapeHtml(name) + ', в' : 'В'}ведіть цей код у застосунку OstrovUA:
      </td></tr>
      <tr><td align="center" style="padding:14px 0;background:#0f1520;border-radius:12px;
        font-size:32px;font-weight:800;letter-spacing:8px;color:#d7f56b">${code}</td></tr>
      <tr><td style="font-size:12px;color:#7d8a9a;padding-top:20px">
        Код діє 15 хвилин. Якщо ви не просили відновлення — просто проігноруйте цей лист,
        пароль лишиться незмінним.
      </td></tr>
    </table>
  </td></tr></table>
</body></html>`;
}

async function sendResetEmail({ to, name, code }) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY не налаштовано');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: RESEND_FROM,
      to: [to],
      subject: 'Код відновлення пароля — OstrovUA',
      html: resetEmailHTML({ name, code }),
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Resend ${res.status}: ${body.slice(0, 300)}`);
  }
}

const RESET_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function generateResetCode() {
  let raw = '';
  for (let i = 0; i < 12; i += 1) {
    raw += RESET_CODE_ALPHABET[crypto.randomInt(0, RESET_CODE_ALPHABET.length)];
  }
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}
function normalizeResetCode(code) {
  return String(code || '').toUpperCase().replace(/[\s-]/g, '');
}
function passwordResetHash(contributorId, code) {
  return crypto
    .createHmac('sha256', PASSWORD_RESET_PEPPER)
    .update(`${contributorId}:${normalizeResetCode(code)}`, 'utf8')
    .digest('hex');
}

app.post('/auth/forgot-password', rateLimit, async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();

  // Однакова відповідь у будь-якому разі — щоб не можна було
  // перебором з'ясувати, хто є в базі.
  const same = () => res.json({ ok: true });
  if (!email) return same();
  try {
    const result = await consumeAuthRateLimit({
      bucket: 'forgot:email',
      identity: `email:${email}`,
      limit: 3,
      windowSeconds: 3600,
      blockSeconds: 3600,
    });
    if (!result.allowed) return same();
  } catch (error) {
    console.error('[forgot-password-rate-limit]', error.message);
    return res.status(503).json({ error: 'Захист відновлення тимчасово недоступний' });
  }

  try {
    const data = await hasuraAdmin(
      `query($email: String!) {
         contributors(where:{email:{_eq:$email}}, limit:1) { id name password_hash }
       }`, { email }
    );
    const c = data.contributors?.[0];
    if (!c) return same();

    const code = generateResetCode();
    const expiresAt = new Date(Date.now() + 15 * 60_000).toISOString();

    await hasuraAdmin(
      `mutation($contributorId: uuid!, $obj: password_resets_insert_input!) {
         update_password_resets(
           where:{contributor_id:{_eq:$contributorId}, used:{_eq:false}},
           _set:{used:true}
         ) { affected_rows }
         insert_password_resets_one(object: $obj) { id }
       }`,
      {
        contributorId: c.id,
        obj: {
          contributor_id: c.id,
          code_hash: passwordResetHash(c.id, code),
          expires_at: expiresAt,
        },
      }
    );

    await sendResetEmail({ to: email, name: c.name, code });
    return same();
  } catch (e) {
    console.error('[forgot-password]', e.message);
    return same();
  }
});

app.post('/auth/reset-password', rateLimit, async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.code || '').trim();
  const newPassword = req.body?.newPassword || '';

  if (!email || !code || !newPassword) {
    return res.status(400).json({ error: 'Вкажи пошту, код і новий пароль' });
  }
  const passwordPolicy = validateNewPassword(newPassword, { email });
  if (!passwordPolicy.ok) return res.status(400).json({ error: passwordPolicy.error });
  if (!await enforceIdentityRateLimit(res, {
    bucket: 'reset:email',
    identity: `email:${email}`,
    limit: 5,
    windowSeconds: 900,
    blockSeconds: 3600,
  })) return;

  try {
    const data = await hasuraAdmin(
      `query($email: String!) {
         contributors(where:{email:{_eq:$email}}, limit:1) { id }
       }`, { email }
    );

    const c = data.contributors?.[0];
    if (!c) return res.status(400).json({ error: 'Код недійсний або протермінований' });

    const hash = await hashPassword(passwordPolicy.normalized, bcrypt, BCRYPT_ROUNDS);
    const outcome = await authSecurityStore.resetPassword({
      contributorId: c.id,
      candidateHash: passwordResetHash(c.id, code),
      passwordHash: hash,
    });
    if (outcome === 'attempts_exhausted') {
      return res.status(429).json({ error: 'Забагато спроб. Замов новий код.' });
    }
    if (outcome !== 'changed') {
      return res.status(400).json({ error: 'Код недійсний або протермінований' });
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error('[reset-password]', e.message);
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});

// ── UPDATE AVATAR ──────────────────────────────────────────────────────────────
app.post('/auth/update-avatar', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const { photo_url } = req.body || {};
  if (!photo_url) return res.status(400).json({ error: 'photo_url обов\'язковий' });

  // Profile uploads are always re-encoded by the first-party frontend. Accept
  // only canonical raster data URLs whose declared MIME matches magic bytes.
  // This excludes SVG/HTML polyglots, external tracking URLs and mixed content.
  const canonicalPhoto = normalizeAvatarDataUrl(photo_url);
  if (!canonicalPhoto) {
    return res.status(400).json({ error: 'Фото має бути JPEG, PNG або WebP до 2 МБ' });
  }

  try {
    const data = await hasuraAdmin(
      `mutation($id: uuid!, $photo: String!) {
         update_contributors_by_pk(
           pk_columns: {id: $id},
           _set: { photo_url: $photo, consent_level: "full" }
         ) { id photo_url consent_level }
       }`,
      { id: contributorId, photo: canonicalPhoto }
    );
    if (!data.update_contributors_by_pk) {
      return res.status(404).json({ error: 'Учасника не знайдено' });
    }
    return res.json({ ok: true, photo_url: data.update_contributors_by_pk.photo_url });
  } catch(e) {
    console.error('[update-avatar]', e.message);
    return res.status(500).json({ error: 'Помилка збереження' });
  }
});

// ── UPDATE THEME (UI preference, dark/light) ────────────────────────────────────
app.post('/auth/update-theme', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const { theme } = req.body || {};
  if (theme !== 'dark' && theme !== 'light') {
    return res.status(400).json({ error: 'Невалідна тема (dark|light)' });
  }

  try {
    const data = await hasuraAdmin(
      `mutation($id: uuid!, $theme: String!) {
         update_contributors_by_pk(
           pk_columns: {id: $id},
           _set: { theme: $theme }
         ) { id theme }
       }`,
      { id: contributorId, theme }
    );
    if (!data.update_contributors_by_pk) {
      return res.status(404).json({ error: 'Учасника не знайдено' });
    }
    return res.json({ ok: true, theme: data.update_contributors_by_pk.theme });
  } catch(e) {
    console.error('[update-theme]', e.message);
    return res.status(500).json({ error: 'Помилка збереження' });
  }
});

// ── INVITE: координатор створює інвайт і надсилає лист ───────────────────────────
app.post('/auth/invite', rateLimit, async (req, res) => {
  const callerId = await requireContributor(req, res);
  if (!callerId) return;
  if (!(await isCoordinator(callerId))) {
    return res.status(403).json({ error: 'Лише координатор може запрошувати' });
  }

  const email = (req.body?.email || '').trim().toLowerCase();
  const name  = (req.body?.name  || '').trim();
  const role  = (req.body?.role  || '').trim();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ error: 'Невалідний email' });
  }
  if (!name) return res.status(400).json({ error: 'Вкажи ім\'я запрошеного' });

  try {
    // Вже зареєстрований?
    const exist = await hasuraAdmin(
      `query($email: String!) { contributors(where:{email:{_eq:$email}}, limit:1) { id password_hash } }`,
      { email }
    );
    if (exist.contributors?.[0]?.password_hash) {
      return res.status(409).json({ error: 'Користувач з таким email вже зареєстрований' });
    }

    const token     = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 86400_000).toISOString();
    const invitedBy = req.authPayload?.name || callerId;

    await hasuraAdmin(
      `mutation($obj: invited_emails_insert_input!) {
         insert_invited_emails_one(
           object: $obj,
           on_conflict: {
             constraint: invited_emails_pkey,
             update_columns: [token, name, role, used, used_at, expires_at, invited_by]
           }
         ) { email }
       }`,
      { obj: { email, name, role, token, used: false, used_at: null, expires_at: expiresAt, invited_by: invitedBy } }
    );

    const link = `${PUBLIC_APP_URL}/?invite_token=${token}`;
    await sendInviteEmail({ to: email, name, role, link });

    return res.json({ ok: true, email });
  } catch (e) {
    console.error('[invite]', e.message);
    // Якщо рядок створено, але лист не пішов — повідомляємо саме про лист.
    const isMail = /Resend|RESEND/.test(e.message);
    return res.status(isMail ? 502 : 500).json({
      error: isMail ? 'Не вдалося надіслати лист. Перевір налаштування Resend.' : 'Помилка створення запрошення',
    });
  }
});

// ── INVITE: дані за токеном (prefill сторінки створення пароля) ──────────────────
app.get('/auth/invite/:token', async (req, res) => {
  const token = req.params.token || '';
  try {
    const data = await hasuraAdmin(
      `query($t: String!) {
         invited_emails(where:{ token:{_eq:$t}, used:{_eq:false} }, limit:1)
         { email name role expires_at }
       }`,
      { t: token }
    );
    const inv = data.invited_emails?.[0];
    if (!inv) return res.status(404).json({ error: 'Запрошення не знайдено або вже використане' });
    if (inv.expires_at && new Date(inv.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Термін дії запрошення вичерпано' });
    }
    return res.json({ email: inv.email, name: inv.name, role: inv.role });
  } catch (e) {
    console.error('[invite-get]', e.message);
    return res.status(500).json({ error: 'Помилка перевірки запрошення' });
  }
});

// ── INVITE: користувач задає пароль за токеном і одразу входить ──────────────────
app.post('/auth/accept-invite', rateLimit, async (req, res) => {
  const token    = (req.body?.token || '').trim();
  const password = req.body?.password || '';
  if (!token) return res.status(400).json({ error: 'Відсутній токен запрошення' });

  try {
    const data = await hasuraAdmin(
      `query($t: String!) {
         invited_emails(where:{ token:{_eq:$t}, used:{_eq:false} }, limit:1)
         { email name role expires_at }
       }`,
      { t: token }
    );
    const inv = data.invited_emails?.[0];
    if (!inv) return res.status(404).json({ error: 'Запрошення не знайдено або вже використане' });
    if (inv.expires_at && new Date(inv.expires_at) < new Date()) {
      return res.status(410).json({ error: 'Термін дії запрошення вичерпано' });
    }

    const email = inv.email;
    const name  = inv.name || 'Учасник';
    const role  = inv.role || 'Учасник';
    const passwordPolicy = validateNewPassword(password, { email, name });
    if (!passwordPolicy.ok) return res.status(400).json({ error: passwordPolicy.error });
    const password_hash = await hashPassword(passwordPolicy.normalized, bcrypt, BCRYPT_ROUNDS);

    // Якщо контакт уже існує (напр. створений координатором/OAuth без пароля) — оновлюємо.
    const exist = await hasuraAdmin(
      `query($email: String!) { contributors(where:{email:{_eq:$email}}, limit:1) { id password_hash } }`,
      { email }
    );
    let c;
    if (exist.contributors?.[0]) {
      if (exist.contributors[0].password_hash) {
        return res.status(409).json({ error: 'Користувач вже зареєстрований. Скористайся входом.' });
      }
      const upd = await hasuraAdmin(
        `mutation($id: uuid!, $obj: contributors_set_input!) {
           update_contributors_by_pk(pk_columns:{id:$id}, _set:$obj)
           { id name role photo_url consent_level }
         }`,
        { id: exist.contributors[0].id, obj: { password_hash, name, role, status: 'active' } }
      );
      c = upd.update_contributors_by_pk;
    } else {
      const ins = await hasuraAdmin(
        `mutation($obj: contributors_insert_input!) {
           insert_contributors_one(object:$obj)
           { id name role photo_url consent_level }
         }`,
        { obj: { name, role, email, password_hash, status: 'active', description: '', consent_level: 'none' } }
      );
      c = ins.insert_contributors_one;
    }

    // Гасимо інвайт (одноразовий).
    await hasuraAdmin(
      `mutation($t: String!, $at: timestamptz!) {
         update_invited_emails(where:{token:{_eq:$t}}, _set:{ used:true, used_at:$at }) { affected_rows }
       }`,
      { t: token, at: new Date().toISOString() }
    );

    return res.json({
      token: await issueToken(c, req),
      contributor: safe(await withTheme(c)),
    });
  } catch (e) {
    console.error('[accept-invite]', e.message);
    return res.status(500).json({ error: 'Помилка активації запрошення' });
  }
});

// ── PROFILE VERIFICATION (server-authoritative) ────────────────────────────────
// The client submits an attested verification session and encrypted evidence.
// Client-reported NFC, passive-auth, AA/CA, face-match and PAD results are never
// sufficient to activate Verified ID. iOS is bound with Apple App Attest;
// unsupported platforms must fail closed until equivalent attestation exists.
const appattest = require('./appattest');
const passiveauth = require('./passiveauth');
const verificationPolicy = require('./verification_policy');
const { parseSelfHostedEnvelope } = require('./self_hosted_contract');
const biometricClient = require('./biometric_client');
const documentCA = DOCUMENT_CA_SEALING_KEY
  ? createDocumentCA(DOCUMENT_CA_SEALING_KEY)
  : null;
if (DOCUMENT_CA_SEALING_KEY) {
  DOCUMENT_CA_SEALING_KEY.fill(0);
  DOCUMENT_CA_SEALING_KEY = null;
}
const {
  createProductionVerificationStore,
} = require('./production_verification_store');
const verificationStore = createProductionVerificationStore(hasuraSQL);

async function authenticateBearer(req, { allowMissing = false } = {}) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return allowMissing ? { status: 'anonymous' } : { status: 'invalid' };
  }
  let payload;
  try {
    payload = jwt.verify(auth.slice(7), JWT_SECRET);
  } catch (_) {
    return { status: 'invalid' };
  }
  const id = payload['https://hasura.io/jwt/claims']?.['x-hasura-contributor-id'];
  if (!id || payload.sub !== id) return { status: 'invalid' };

  if (payload.sid) {
    const active = await authSecurityStore.isSessionActive({
      sessionId: payload.sid,
      contributorId: id,
    });
    if (!active) return { status: 'invalid' };
  } else if (AUTH_SESSION_ENFORCEMENT_ENABLED) {
    return { status: 'invalid' };
  }
  return { status: 'authenticated', contributorId: id, payload };
}

// helper: дістати contributorId з JWT, перевірити server-side session або
// відповісти fail-closed. req.authPayload потрібен для точного logout session.
async function requireContributor(req, res) {
  try {
    const auth = await authenticateBearer(req);
    if (auth.status !== 'authenticated') {
      res.status(401).json({ error: 'Недійсний або відкликаний токен' });
      return null;
    }
    req.authPayload = auth.payload;
    return auth.contributorId;
  } catch (error) {
    console.error('[auth-session-check]', error.message);
    res.status(503).json({ error: 'Перевірка сесії тимчасово недоступна' });
    return null;
  }
}

// Nginx auth_request uses this endpoint in front of Hasura. Anonymous GraphQL
// remains possible under Hasura's anonymous role, but every presented bearer
// token must be valid and not revoked.
app.get('/auth/introspect', async (req, res) => {
  try {
    const auth = await authenticateBearer(req, { allowMissing: true });
    return auth.status === 'invalid' ? res.sendStatus(401) : res.sendStatus(204);
  } catch (error) {
    console.error('[auth-introspect]', error.message);
    return res.sendStatus(503);
  }
});

app.post('/auth/logout', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;
  try {
    const sessionId = req.authPayload?.sid;
    if (sessionId) {
      await authSecurityStore.revokeSession({ sessionId, contributorId });
    }
    return res.json({ ok: true });
  } catch (error) {
    console.error('[auth-logout]', error.message);
    return res.status(503).json({ error: 'Не вдалося відкликати сесію' });
  }
});

app.post('/auth/logout-all', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;
  try {
    await authSecurityStore.revokeAllSessions(contributorId);
    return res.json({ ok: true });
  } catch (error) {
    console.error('[auth-logout-all]', error.message);
    return res.status(503).json({ error: 'Не вдалося відкликати сесії' });
  }
});

// Челендж для attestKey / assertion (одноразовий, TTL 5 хв).
app.post('/auth/verify/challenge', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const purpose = req.body?.purpose;
  const verificationMode = req.body?.verificationMode == null
    ? 'production'
    : req.body.verificationMode;
  if (!['attestation', 'liveness', 'document_auth'].includes(purpose) ||
      !['production', 'calibration'].includes(verificationMode) ||
      (purpose === 'attestation' && verificationMode !== 'production')) {
    return res.status(400).json({ error: 'Недопустиме призначення challenge' });
  }
  const calibrationChallenge = purpose !== 'attestation' &&
    verificationMode === 'calibration';
  if (calibrationChallenge && !verificationPolicy.isBiometricShadowAllowed(
    contributorId,
    process.env.BIOMETRIC_SHADOW_MODE_ENABLED,
    process.env.BIOMETRIC_SHADOW_TESTER_IDS
  )) {
    return res.status(403).json({
      error: 'Тестовий режим біометрії недоступний для цього акаунта.',
      code: 'CALIBRATION_MODE_FORBIDDEN',
    });
  }
  // Не змушуємо людину проходити NFC/PAD, коли production rollout
  // навмисно закритий. Перевіряємо kill-switch ДО rate-limit і ДО видачі
  // біометричного ключа: спроба не рахується, кадри не збираються.
  if (['liveness', 'document_auth'].includes(purpose) && !calibrationChallenge &&
      !verificationPolicy.isSelfHostedVerificationEnabled()) {
    return res.status(503).json({
      error: 'Автоматична верифікація ще не активована. Спробуй пізніше.',
      code: 'SELF_HOSTED_VERIFICATION_DISABLED',
      retryable: true,
    });
  }

  // ЛІМІТ СПРОБ liveness (анти-реплей перебору): кожна спроба бере свіжий
  // challenge → рахуємо видачі на АКАУНТ+ПРИСТРІЙ (rlKeysFor читає uuid і
  // заголовок x-attest-key). Закритий calibration lane не може активувати
  // Verified ID і доступний лише точному server-side allowlist, тому для
  // нього лишається burst-limit middleware без багатогодинної ескалації.
  if (purpose === 'liveness' && !calibrationChallenge) {
    try {
      for (const key of rlKeysFor(contributorId, req)) {
        const r = await rlTouch(key);   // SELECT … FOR UPDATE — без гонок
        if (r.locked) return res.status(429).json({ error: rlLockedMessage(r.until) });
      }
    } catch (e) {
      console.error('[verify/challenge] rate-limit unavailable');
      return res.status(503).json({
        error: 'Захист від повторних спроб тимчасово недоступний. Спробуй пізніше.',
        code: 'VERIFICATION_RATE_LIMIT_UNAVAILABLE',
        retryable: true,
      });
    }
  }
  // document_auth видається під час уже активного NFC-сеансу безпосередньо
  // перед AA/CA і не повинен вдруге інкрементувати одну людську спробу.
  // Критичний endpoint усе одно залежить від доступного persistent limiter:
  // rlCheck читає той самий рядок під транзакційним lock і fail-closed
  // повертає поточний стан.
  if (purpose === 'document_auth' && !calibrationChallenge) {
    try {
      for (const key of rlKeysFor(contributorId, req)) {
        const r = await rlCheck(key);
        if (r.locked) return res.status(429).json({ error: rlLockedMessage(r.until) });
      }
    } catch (e) {
      console.error('[verify/challenge] rate-limit unavailable');
      return res.status(503).json({
        error: 'Захист від повторних спроб тимчасово недоступний. Спробуй пізніше.',
        code: 'VERIFICATION_RATE_LIMIT_UNAVAILABLE',
        retryable: true,
      });
    }
  }

  try {
    const storedPurpose = calibrationChallenge
      ? `${purpose}_calibration`
      : purpose;
    const {
      id, challenge, expiresAt, expiresInSeconds,
    } = appattest.issueChallenge(contributorId, storedPurpose);
    if (purpose === 'liveness') {
      const key = biometricClient.loadEnvelopePublicKey();
      return res.json({
        challengeId: id,
        challenge,
        expiresAt,
        expiresInSeconds,
        biometricKeyId: key.keyId,
        biometricPublicKey: key.publicKey,
      });
    }
    return res.json({
      challengeId: id,
      challenge,
      expiresAt,
      expiresInSeconds,
      // Capability only; never an assurance result. The client uses it to
      // avoid invoking the relay during dark deployment. /approve still
      // requires the independently verified one-time database receipt.
      serverOwnedCAEnabled: purpose === 'document_auth' &&
        serverOwnedCALane(contributorId, verificationMode),
    });
  } catch (e) {
    return res.status(503).json({ error: 'Спробуй пізніше.' });
  }
});


// Реєстрація ключа пристрою (перший запуск застосунку).
// Body: { challengeId, keyId (b64), attestation (b64 CBOR) }
app.post('/auth/verify/attest-key', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;
  const { challengeId, keyId, attestation } = req.body || {};
  if (!challengeId || !keyId || !attestation) return res.status(400).json({ error: 'challengeId, keyId, attestation обов\'язкові' });

  const challengeBytes = appattest.consumeChallenge(challengeId, contributorId, 'attestation');
  if (!challengeBytes) return res.status(400).json({ error: 'Челендж недійсний або протермінований' });

  try {
    const { publicKeyPem, environment } = appattest.verifyAttestation({
      attestationB64: attestation, keyIdB64: keyId, challengeBytes,
    });
    await hasuraAdmin(
      `mutation($obj: attest_keys_insert_input!) {
         insert_attest_keys_one(object:$obj,
           on_conflict:{constraint: attest_keys_pkey, update_columns:[public_key_pem, environment, counter]}) { key_id }
       }`,
      { obj: { key_id: keyId, contributor_id: contributorId, public_key_pem: publicKeyPem, environment, counter: 0 } }
    );
    return res.json({ ok: true });
  } catch (e) {
    console.warn('[verify/attest-key]', e.message);
    return res.status(403).json({ error: 'Attestation відхилено' });
  }
});

// Assertion iOS: headers x-app-attest (b64 CBOR) + x-attest-key (b64 keyId),
// body.challengeId — челендж, виданий цьому користувачу.
async function verifyAppAttestAssertion(req, contributorId) {
  const assertionB64 = req.headers['x-app-attest'];
  const keyId        = req.headers['x-attest-key'];
  const challengeId  = req.body?.challengeId;
  if (!assertionB64 || !keyId || !challengeId) return false;

  const challengeBytes = appattest.consumeChallenge(challengeId, contributorId, 'attestation');
  if (!challengeBytes) return false;

  try {
    const d = await hasuraAdmin(
      `query($k: String!, $c: uuid!) {
         attest_keys(where:{key_id:{_eq:$k}, contributor_id:{_eq:$c}}, limit:1)
         { key_id public_key_pem counter }
       }`,
      { k: keyId, c: contributorId }
    );
    const rec = d.attest_keys?.[0];
    if (!rec) return false;

    const newCounter = appattest.verifyAssertion({
      assertionB64, publicKeyPem: rec.public_key_pem,
      challengeBytes,
      bodyBytes: req.rawBody,          // дослівні байти canonical payload
      storedCounter: rec.counter,
    });
    // АТОМАРНО (compare-and-swap, аудит P1-03): counter приймається
    // лише якщо в БАЗІ він досі менший — два паралельні запити з тим
    // самим assertion не пройдуть обидва (перший виграє, другий — 0 рядків).
    const upd = await hasuraAdmin(
      `mutation($k: String!, $n: bigint!, $at: timestamptz!) {
         update_attest_keys(
           where:{ key_id:{_eq:$k}, counter:{_lt:$n} },
           _set:{ counter:$n, last_used_at:$at }) { affected_rows }
       }`,
      { k: keyId, n: newCounter, at: new Date().toISOString() }
    );
    if ((upd.update_attest_keys?.affected_rows ?? 0) !== 1) {
      console.warn('[verify/assertion] counter CAS conflict (можливий replay)');
      return false;
    }
    return true;
  } catch (e) {
    console.warn('[verify/assertion]', e.message);
    return false;
  }
}

// Єдина точка атестації пристрою. iOS App Attest — єдиний підтримуваний
// шлях зараз. Жодного dev-bypass у коді (аудит #5): раніше існував
// VERIFY_DEV_BYPASS — його ФІЗИЧНО ВИДАЛЕНО, обійти атестацію збіркою
// чи змінною середовища неможливо.
// Android (Play Integrity) — окремий майбутній маршрут з власним
// nonce-binding до тіла запиту; поки НЕ підтримується і НЕ приймається
// (аудит #6: «висячої» гілки більше немає).
async function verifyDeviceAttestation(req, contributorId) {
  if (req.headers['x-app-attest']) return verifyAppAttestAssertion(req, contributorId);
  return false;
}

function serverOwnedCALane(contributorId, verificationMode) {
  if (process.env.SERVER_OWNED_CA_ENABLED !== '1' || !documentCA) return false;
  if (verificationMode === 'production') {
    return verificationPolicy.isSelfHostedVerificationEnabled();
  }
  return verificationMode === 'calibration' &&
    verificationPolicy.isBiometricShadowAllowed(contributorId);
}

async function enforceServerOwnedCARateLimit(req, res, contributorId, evaluationOnly) {
  if (evaluationOnly) return true;
  try {
    for (const key of rlKeysFor(contributorId, req)) {
      const result = await rlCheck(key);
      if (result.locked) {
        res.status(429).json({ error: rlLockedMessage(result.until) });
        return false;
      }
    }
    return true;
  } catch {
    res.status(503).json({
      error: 'Захист Chip Authentication тимчасово недоступний.',
      code: 'VERIFICATION_RATE_LIMIT_UNAVAILABLE',
      retryable: true,
    });
    return false;
  }
}

// Begin a server-owned Chip Authentication transcript. App Attest signs the
// exact request body. DG14 is parsed independently here; the client cannot
// select a weaker algorithm or provide a CA result bit.
app.post('/auth/verify/ca/start', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;
  const body = req.body || {};
  const expectedKeys = [
    'challengeId', 'documentChallengeId', 'endpoint', 'rawDG14',
    'verificationMode',
  ];
  if (Object.keys(body).sort().join(',') !== expectedKeys.sort().join(',') ||
      body.endpoint !== '/auth/verify/ca/start' ||
      !['production', 'calibration'].includes(body.verificationMode) ||
      typeof body.rawDG14 !== 'string') {
    return res.status(400).json({ error: 'Некоректний CA start payload' });
  }
  const evaluationOnly = body.verificationMode === 'calibration';
  if (!serverOwnedCALane(contributorId, body.verificationMode)) {
    return res.status(503).json({
      error: 'Server-owned Chip Authentication ще не активовано.',
      code: 'SERVER_OWNED_CA_DISABLED',
      retryable: true,
    });
  }
  if (!await enforceServerOwnedCARateLimit(req, res, contributorId, evaluationOnly)) return;
  if (!await verifyDeviceAttestation(req, contributorId)) {
    return res.status(403).json({ error: 'Device attestation required' });
  }
  const purpose = evaluationOnly ? 'document_auth_calibration' : 'document_auth';
  const documentChallenge = appattest.inspectChallenge(
    body.documentChallengeId,
    contributorId,
    purpose
  );
  if (!documentChallenge) {
    return res.status(400).json({
      error: 'Недійсний або протермінований challenge документа',
      code: 'DOCUMENT_CHALLENGE_INVALID',
    });
  }
  documentChallenge.fill(0);

  try {
    const started = documentCA.start({
      rawDG14: body.rawDG14,
      contributorId,
      attestKeyId: req.headers['x-attest-key'],
      documentChallengeId: body.documentChallengeId,
    });
    return res.json({
      sessionId: started.sessionId,
      expiresAt: started.expiresAt,
      option: started.option,
      ephemeralPublicKey: started.ephemeralPublicKey,
      protectedCommand: started.protectedCommand,
      token: started.token,
    });
  } catch (error) {
    if (['ca_unsupported', 'ca_curve_unsupported'].includes(error?.code)) {
      return res.status(422).json({
        error: 'Цей документ не підтримує дозволений server-owned CA профіль.',
        code: 'SERVER_OWNED_CA_UNSUPPORTED',
      });
    }
    if (typeof error?.code === 'string' && error.code.startsWith('ca_')) {
      return res.status(400).json({
        error: 'DG14 не пройшла незалежний CA розбір.',
        code: 'SERVER_OWNED_CA_DG14_INVALID',
      });
    }
    console.error('[verify/ca/start] unavailable');
    return res.status(503).json({
      error: 'Chip Authentication тимчасово недоступна.',
      code: 'SERVER_OWNED_CA_UNAVAILABLE',
      retryable: true,
    });
  } finally {
    body.rawDG14 = null;
    if (Buffer.isBuffer(req.rawBody)) req.rawBody.fill(0);
  }
});

// Complete the transcript. The auth service verifies the protected RAPDU MAC,
// decrypts the challenge response and stores only a one-time, non-biometric
// receipt. It never stores DG14, APDUs or derived session keys.
app.post('/auth/verify/ca/complete', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;
  const body = req.body || {};
  const expectedKeys = [
    'challengeId', 'documentChallengeId', 'endpoint', 'responseData',
    'sw1', 'sw2', 'token', 'verificationMode',
  ];
  if (Object.keys(body).sort().join(',') !== expectedKeys.sort().join(',') ||
      body.endpoint !== '/auth/verify/ca/complete' ||
      !['production', 'calibration'].includes(body.verificationMode) ||
      typeof body.token !== 'string' ||
      typeof body.responseData !== 'string') {
    return res.status(400).json({ error: 'Некоректний CA complete payload' });
  }
  const evaluationOnly = body.verificationMode === 'calibration';
  if (!serverOwnedCALane(contributorId, body.verificationMode)) {
    return res.status(503).json({
      error: 'Server-owned Chip Authentication ще не активовано.',
      code: 'SERVER_OWNED_CA_DISABLED',
      retryable: true,
    });
  }
  if (!await enforceServerOwnedCARateLimit(req, res, contributorId, evaluationOnly)) return;
  if (!await verifyDeviceAttestation(req, contributorId)) {
    return res.status(403).json({ error: 'Device attestation required' });
  }
  const purpose = evaluationOnly ? 'document_auth_calibration' : 'document_auth';
  const documentChallenge = appattest.inspectChallenge(
    body.documentChallengeId,
    contributorId,
    purpose
  );
  if (!documentChallenge) {
    return res.status(400).json({
      error: 'Недійсний або протермінований challenge документа',
      code: 'DOCUMENT_CHALLENGE_INVALID',
    });
  }
  documentChallenge.fill(0);

  try {
    const completed = documentCA.complete({
      token: body.token,
      contributorId,
      attestKeyId: req.headers['x-attest-key'],
      documentChallengeId: body.documentChallengeId,
      responseData: body.responseData,
      sw1: body.sw1,
      sw2: body.sw2,
    });
    const recorded = await authSecurityStore.recordDocumentCAReceipt(completed);
    if (!recorded) {
      return res.status(409).json({
        error: 'CA transcript уже використано.',
        code: 'SERVER_OWNED_CA_REPLAYED',
      });
    }
    return res.json({
      ok: true,
      sessionId: completed.sessionId,
      expiresAt: completed.expiresAt,
    });
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('ca_')) {
      return res.status(400).json({
        error: 'Chip Authentication transcript відхилено.',
        code: 'SERVER_OWNED_CA_TRANSCRIPT_INVALID',
      });
    }
    console.error('[verify/ca/complete] receipt unavailable');
    return res.status(503).json({
      error: 'Chip Authentication тимчасово недоступна.',
      code: 'SERVER_OWNED_CA_UNAVAILABLE',
      retryable: true,
    });
  } finally {
    body.token = null;
    body.responseData = null;
    if (Buffer.isBuffer(req.rawBody)) req.rawBody.fill(0);
  }
});

// ── Кросс-девайс сесії верифікації (десктоп → QR → телефон) ────────────────
// В пам'яті, TTL 10 хв. Жодних персональних даних: лише contributorId + статус.
// pending → opened (телефон відкрив) → approved (застосунок підтвердив чип).
const verifySessions = new Map(); // token -> { contributorId, status, expiresAt }
const VERIFY_SESSION_TTL_MS = 10 * 60 * 1000;

function getVerifySession(token) {
  const s = verifySessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expiresAt) { verifySessions.delete(token); return null; }
  return s;
}
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of verifySessions) if (now > s.expiresAt) verifySessions.delete(t);
}, 60 * 1000).unref();

// Десктоп: створити сесію → токен для QR-посилання.
app.post('/auth/verify/session', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const token = crypto.randomBytes(24).toString('base64url');
  verifySessions.set(token, {
    contributorId, status: 'pending', expiresAt: Date.now() + VERIFY_SESSION_TTL_MS,
  });
  return res.json({ token, expiresIn: VERIFY_SESSION_TTL_MS / 1000 });
});

// Десктоп: поллінг статусу. Токен — секрет на пред'явника; віддаємо лише статус.
app.get('/auth/verify/session/:token', (req, res) => {
  const s = getVerifySession(req.params.token);
  return res.json({ status: s ? s.status : 'expired' });
});

// Телефон: позначити, що посилання відкрито (жива індикація на десктопі).
app.post('/auth/verify/session/:token/opened', rateLimit, (req, res) => {
  const s = getVerifySession(req.params.token);
  if (!s) return res.status(410).json({ error: 'Сесію не знайдено або протерміновано' });
  if (s.status === 'pending') s.status = 'opened';
  return res.json({ ok: true });
});

// Строга валідація форми dgHashes (аудит F3): рівно {dg1, dg2},
// кожен — обʼєкт з дозволених алгоритмів → hex-рядок правильної довжини.
const DG_HEX_LENGTHS = { sha1: 40, sha224: 56, sha256: 64, sha384: 96, sha512: 128 };
function isValidDgHashes(v) {
  if (typeof v !== 'object' || v === null) return false;
  const groups = Object.keys(v).sort();
  if (!groups.includes('dg1') || !groups.includes('dg2') ||
      groups.some((dg) => !['dg1', 'dg2', 'dg14', 'dg15'].includes(dg))) {
    return false;
  }
  for (const dg of groups) {
    const group = v[dg];
    if (typeof group !== 'object' || group === null) return false;
    const algs = Object.keys(group);
    if (algs.length === 0 || algs.length > 5) return false;
    for (const alg of algs) {
      const want = DG_HEX_LENGTHS[alg];
      const hex = group[alg];
      if (!want || typeof hex !== 'string' || hex.length !== want ||
          !/^[0-9a-fA-F]+$/.test(hex)) return false;
    }
  }
  return true;
}


app.post('/auth/verify/approve', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return res.status(401).json({ error: 'Не авторизовано' });

  const okAttest = await verifyDeviceAttestation(req, contributorId);
  if (!okAttest) return res.status(403).json({ error: 'Device attestation required' });

  // Тіло — канонічний payload, підписаний App Attest assertion.
  // verifyDeviceAttestation перевіряє assertion над hash(challenge ‖ body)
  // та assertion counter (replay).
  //
  // СТРОГА СХЕМА (аудит P0-05, F3): відхиляємо НЕВІДОМІ ключі явно —
  // JS-деструктуризація сама їх не ловить. Дозволений рівно цей набір.
  const body = req.body || {};
  const ALLOWED_KEYS = new Set([
    'method', 'liveness', 'faceMatch', 'faceModel', 'sod', 'dgHashes',
    'biometricEnvelope', 'verificationMode',
    'protocolVersion', 'endpoint', 'challengeId', 'session',
    'activeLiveness', 'activeLivenessChallengeId', 'activeLivenessEvidence',
    'documentAuthenticationChallengeId', 'chipAuthentication',
    'activeAuthentication',
    'faceModelVersion', 'faceMatchScore', 'faceMatchThreshold',
    'faceSampleCount', 'faceContinuityScore',
  ]);
  const extraneous = Object.keys(body).filter(k => !ALLOWED_KEYS.has(k));
  if (extraneous.length) {
    return res.status(400).json({ error: 'Невідомі поля payload: ' + extraneous.join(', ') });
  }

  const { method, session, liveness, faceMatch, faceModel, sod, dgHashes,
          protocolVersion, endpoint, challengeId,
          activeLiveness, activeLivenessChallengeId,
          documentAuthenticationChallengeId, chipAuthentication,
          activeAuthentication } = body;
  const verificationMode = body.verificationMode === undefined
    ? 'production'
    : body.verificationMode;
  if (verificationMode !== 'production' && verificationMode !== 'calibration') {
    return res.status(400).json({ error: 'Недопустимий режим верифікації' });
  }
  const evaluationOnly = verificationMode === 'calibration';
  if (evaluationOnly && protocolVersion !== verificationPolicy.PROTOCOL_VERSION) {
    return res.status(400).json({ error: 'Тестовий режим потребує актуальної версії застосунку' });
  }
  // UI видимий у TestFlight не є межею безпеки: сервер окремо перевіряє
  // закритий allowlist contributor UUID. Невідомий акаунт не запускає worker.
  if (evaluationOnly && !verificationPolicy.isBiometricShadowAllowed(contributorId)) {
    return res.status(403).json({
      error: 'Тестовий режим недоступний для цього акаунта.',
      code: 'CALIBRATION_MODE_FORBIDDEN',
    });
  }
  // Approve є окремою критичною межею. Навіть якщо liveness challenge уже
  // було видано, недоступність або lock persistent limiter не дозволяє
  // дійти до PA, біометричного worker'а чи мутації Verified ID.
  if (!evaluationOnly) {
    try {
      for (const key of rlKeysFor(contributorId, req)) {
        const r = await rlCheck(key);
        if (r.locked) return res.status(429).json({ error: rlLockedMessage(r.until) });
      }
    } catch (e) {
      console.error('[verify/approve] rate-limit unavailable');
      return res.status(503).json({
        error: 'Захист від повторних спроб тимчасово недоступний. Спробуй пізніше.',
        code: 'VERIFICATION_RATE_LIMIT_UNAVAILABLE',
        retryable: true,
      });
    }
  }

  if (method !== 'nfc_passport') {
    return res.status(400).json({ error: 'Недопустимий метод верифікації' });
  }
  // Активна liveness (challenge-response) — ОБОВʼЯЗКОВА, з привʼязкою
  // до серверного nonce (анти-реплей): challengeId має бути виданий
  // цьому користувачу й свіжий. consumeChallenge гарантує одноразовість.
  if (activeLiveness !== 'passed') {
    return res.status(400).json({ error: 'Активну перевірку присутності не пройдено' });
  }
  let activeChallengeBytes = null;
  {
    const expectedChallengePurpose = evaluationOnly
      ? 'liveness_calibration'
      : 'liveness';
    activeChallengeBytes = typeof activeLivenessChallengeId === 'string'
      ? appattest.consumeChallenge(
        activeLivenessChallengeId,
        contributorId,
        expectedChallengePurpose
      )
      : null;
    if (!activeChallengeBytes) {
      return res.status(400).json({ error: 'Недійсний або протермінований challenge активної liveness' });
    }
  }
  if (endpoint !== '/auth/verify/approve') {
    return res.status(400).json({ error: 'Недопустимий payload' });
  }
  // challengeId завжди додає AppAttestService перед канонізацією (F2).
  if (typeof challengeId !== 'string' || challengeId.length === 0) {
    return res.status(400).json({ error: 'challengeId обовʼязковий' });
  }
  // session — опційний токен десктоп-QR-сесії; якщо є, лише рядок.
  if (session !== undefined && typeof session !== 'string') {
    return res.status(400).json({ error: 'Недопустимий session' });
  }
  // Device-side метрики — лише App-Attest-підписаний pre-check. У v7
  // рішення ухвалюється заново із сирих DG та кадрів в ізольованому
  // одноразовому self-hosted worker'і. Legacy-протоколи не приймаються.
  const biometric = verificationPolicy.validateBiometricEvidence(body, activeChallengeBytes);
  if (!biometric.ok) return res.status(400).json({ error: biometric.error });
  // Окремий операційний kill switch. Навіть коректно відкалібрований worker
  // не може автоматично видати Verified ID, доки rollout не схвалено явно.
  if (protocolVersion === verificationPolicy.PROTOCOL_VERSION &&
      !evaluationOnly &&
      !verificationPolicy.isSelfHostedVerificationEnabled()) {
    return res.status(503).json({
      error: 'Автоматична верифікація ще не активована. Спробуй пізніше.',
      code: 'SELF_HOSTED_VERIFICATION_DISABLED',
      retryable: true,
    });
  }
  if (typeof sod !== 'string' || sod.length === 0 || sod.length > 96 * 1024) {
    return res.status(400).json({ error: 'SOD відсутній або завеликий' });
  }
  // Строга форма dgHashes: рівно {dg1,dg2}, кожен — обʼєкт
  // {алгоритм → hex}, hex лише [0-9a-f], розумної довжини (F3).
  if (!isValidDgHashes(dgHashes)) {
    return res.status(400).json({ error: 'Недопустима форма dgHashes' });
  }

  let documentChallengeBytes = null;
  if (protocolVersion === verificationPolicy.PROTOCOL_VERSION) {
    if (!['passed', 'not_supported'].includes(chipAuthentication) ||
        !['passed', 'not_supported'].includes(activeAuthentication)) {
      return res.status(400).json({ error: 'Некоректний стан автентифікації чипа' });
    }
    const expectedPurpose = evaluationOnly
      ? 'document_auth_calibration'
      : 'document_auth';
    documentChallengeBytes =
      typeof documentAuthenticationChallengeId === 'string'
        ? appattest.consumeChallenge(
          documentAuthenticationChallengeId,
          contributorId,
          expectedPurpose
        )
        : null;
    if (!documentChallengeBytes) {
      return res.status(400).json({
        error: 'Недійсний або протермінований challenge документа',
        code: 'DOCUMENT_CHALLENGE_INVALID',
      });
    }
  }

  // ── Passive Authentication (ICAO 9303): серверна перевірка SOD ────
  // ОБОВʼЯЗКОВА: немає криптодоказу справжності документа — немає
  // Verified ID. Обходу не існує (dev-bypass фізично видалено).
  let pa;
  let serverBiometrics = null;
  let opaqueEnvelope = null;
  try {
    if (protocolVersion === verificationPolicy.PROTOCOL_VERSION) {
      opaqueEnvelope = parseSelfHostedEnvelope(body.biometricEnvelope);
    }

    pa = await passiveauth.verifySOD({
      sodBase64: sod,
      dgHashes,
    });

    if (pa.status === 'passed' && opaqueEnvelope) {
      serverBiometrics = await biometricClient.verifySelfHostedBiometrics(
        opaqueEnvelope,
        verificationPolicy.deriveSequence(activeChallengeBytes),
        activeChallengeBytes,
        documentChallengeBytes,
        evaluationOnly
      );
      if (serverBiometrics.evaluationOnly !== evaluationOnly) {
        throw new Error('biometric_response_mode_mismatch');
      }
      // The first PA pass avoids running expensive biometrics for an invalid
      // document. The authoritative PA pass below uses hashes computed only
      // after decrypting raw DG1/DG2 inside the one-request worker.
      for (const group of Object.keys(dgHashes)) {
        for (const [algorithm, clientHash] of Object.entries(dgHashes[group])) {
          const workerHash = serverBiometrics.dgHashes?.[group]?.[algorithm];
          if (typeof workerHash !== 'string' || workerHash.length !== clientHash.length ||
              !crypto.timingSafeEqual(Buffer.from(workerHash, 'hex'),
                Buffer.from(clientHash.toLowerCase(), 'hex'))) {
            throw new Error('biometric_envelope_dg_hash_mismatch');
          }
        }
      }
      pa = await passiveauth.verifySOD({
        sodBase64: sod,
        dgHashes: serverBiometrics.dgHashes,
      });
      const documentResult = serverBiometrics.documentAuthentication;
      if (!documentResult ||
          documentResult.activeAuthentication !== activeAuthentication) {
        throw new Error('biometric_envelope_document_auth_mismatch');
      }
    }
  } catch (e) {
    const validationFailure = typeof e?.message === 'string' &&
      /^(?:biometric_envelope_|ephemeral_public_key_|envelope_nonce_|envelope_ciphertext_)/.test(e.message);
    if (validationFailure) {
      return res.status(400).json({
        error: 'Некоректний або неповний доказ документа/біометрії.',
        code: 'EVIDENCE_INVALID',
      });
    }
    console.error('[verify/approve] self-hosted verifier unavailable:', e?.message || String(e));
    return res.status(503).json({
      error: 'Перевірка біометрії тимчасово недоступна. Спробуй пізніше.',
      code: 'BIOMETRIC_UNAVAILABLE',
      retryable: true,
    });
  } finally {
    // Auth володіє лише ciphertext. Plaintext DG/frames існують виключно в
    // worker max_requests=1, address space якого ОС знищує після відповіді.
    if (Buffer.isBuffer(req.rawBody)) req.rawBody.fill(0);
    if (Buffer.isBuffer(documentChallengeBytes)) documentChallengeBytes.fill(0);
    if (Buffer.isBuffer(activeChallengeBytes)) activeChallengeBytes.fill(0);
    if (body.biometricEnvelope !== undefined) body.biometricEnvelope = null;
  }

  if (pa.status !== 'passed') {
    console.warn(`[verify/approve] PA REJECT ${contributorId.slice(0,8)}… status=${pa.status} reason=${pa.reason}`);
    const msg = pa.status === 'unavailable'
      ? (pa.reason === 'dsc_not_found'
        ? 'Сервер ще не має сертифіката підписанта цього документа. Документ не відхилено; оновлюємо ICAO PKD.'
        : 'Перевірка справжності документа тимчасово недоступна. Спробуй пізніше.')
      : 'Документ не пройшов криптографічну перевірку справжності';
    return res.status(pa.status === 'unavailable' ? 503 : 400).json({
      error: msg,
      code: pa.reason === 'dsc_not_found' ? 'PA_TRUST_MATERIAL_MISSING' : 'PA_FAILED',
      retryable: pa.status === 'unavailable',
    });
  }

  // Server-owned CA is authoritative only when a still-unused database
  // receipt matches this App Attest key, this document challenge and the DG14
  // digest independently computed inside the isolated worker. A client
  // `chipAuthentication=passed` field cannot create this assurance.
  let serverOwnedCA = false;
  const dg14Hash = serverBiometrics?.dgHashes?.dg14?.sha256;
  if (process.env.SERVER_OWNED_CA_ENABLED === '1' &&
      typeof dg14Hash === 'string' &&
      /^[0-9a-f]{64}$/.test(dg14Hash)) {
    try {
      serverOwnedCA = await authSecurityStore.hasDocumentCAReceipt({
        contributorId,
        attestKeyId: req.headers['x-attest-key'],
        documentChallengeId: documentAuthenticationChallengeId,
        dg14Hash,
      });
    } catch {
      console.error('[verify/approve] server-owned CA receipt lookup unavailable');
      return res.status(503).json({
        error: 'Перевірка Chip Authentication тимчасово недоступна.',
        code: 'SERVER_OWNED_CA_UNAVAILABLE',
        retryable: true,
      });
    }
  }
  const authoritativeDocumentAuthentication = serverBiometrics
    ? {
        ...serverBiometrics.documentAuthentication,
        assurance: serverOwnedCA
          ? 'chip_authentication_server'
          : serverBiometrics.documentAuthentication.assurance,
        chipAuthentication: serverOwnedCA
          ? 'passed'
          : serverBiometrics.documentAuthentication.chipAuthentication,
      }
    : null;

  // Shadow/PAD calibration stops here. It performs the full cryptographic
  // document and isolated biometric evaluation, but cannot derive a document
  // token, create a review request or mutate contributors.verified.
  if (evaluationOnly) {
    if (!serverBiometrics || serverBiometrics.evaluationOnly !== true ||
        serverBiometrics.decision === 'unavailable') {
      return res.status(503).json({
        error: 'Тестова перевірка біометрії тимчасово недоступна.',
        code: 'BIOMETRIC_UNAVAILABLE',
        retryable: true,
      });
    }
    console.log(`[verify/approve] ${contributorId.slice(0,8)}… status=calibration ` +
      `decision=${serverBiometrics.decision} reason=${serverBiometrics.reason} ` +
      `provider=self_hosted_v2`);
    // A fully processed allowlisted calibration run is not an authentication
    // failure and cannot activate Verified ID. Clear the ordinary liveness
    // escalation so repeated physical measurements do not lock the tester.
    // The global per-IP middleware still caps request bursts.
    try { for (const key of rlKeysFor(contributorId, req)) await rlReset(key); }
    catch (e) { console.error('[verify/approve] calibration rl_reset:', e.message); }
    return res.json({
      ok: true,
      status: 'calibration',
      reviewRequired: false,
      verified: false,
      evaluationOnly: true,
      passiveAuthentication: 'passed',
      documentAuthentication: authoritativeDocumentAuthentication,
      decision: serverBiometrics.decision,
      reason: serverBiometrics.reason,
      policyVersion: serverBiometrics.policyVersion,
      modelSetHash: serverBiometrics.modelSetHash,
      metrics: {
        faceMedian: serverBiometrics.faceMedian,
        faceMinimum: serverBiometrics.faceMinimum,
        padMedian: serverBiometrics.padMedian,
        padMinimum: serverBiometrics.padMinimum,
        depthMedianRelief: serverBiometrics.depthMedianRelief,
        depthValidFraction: serverBiometrics.depthValidFraction,
        depthPassed: serverBiometrics.depthPassed,
        challengePassed: serverBiometrics.challengePassed,
      },
      calibrationSignals: serverBiometrics.calibrationSignals,
    });
  }


  if (protocolVersion === verificationPolicy.PROTOCOL_VERSION) {
    if (!serverBiometrics || serverBiometrics.decision === 'unavailable') {
      return res.status(503).json({
        error: 'Перевірка біометрії тимчасово недоступна. Спробуй пізніше.',
        code: 'BIOMETRIC_UNAVAILABLE',
        retryable: true,
      });
    }
    if (serverBiometrics.decision !== 'passed') {
      return res.status(400).json({
        error: 'Не вдалося підтвердити живу присутність і збіг обличчя.',
        code: 'BIOMETRIC_FAILED',
        retryable: true,
      });
    }
  }

  const documentAssurance =
    authoritativeDocumentAuthentication?.assurance || 'passive_only';
  const automaticDocumentAssurance =
    ['active_authentication', 'chip_authentication_server']
      .includes(documentAssurance);

  // ── «Один документ = один акаунт» + бан документа ────────────────
  // token = HMAC(pepper, держ. хеш DG1 із SOD): односторонній,
  // детермінований. Номер паспорта НЕ зберігається і не відновлюється.
  if (!DOC_TOKEN_PEPPER) {
    console.error('[verify/approve] DOC_TOKEN_PEPPER відсутній — верифікація зупинена (fail-closed)');
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }
  const docToken = crypto.createHmac('sha256', DOC_TOKEN_PEPPER)
    .update('doc-token-v1:' + pa.sodDG1Hash).digest('hex');
  const legacyDocToken = LEGACY_DOC_TOKEN_PEPPER && LEGACY_DOC_TOKEN_PEPPER !== DOC_TOKEN_PEPPER
    ? crypto.createHmac('sha256', LEGACY_DOC_TOKEN_PEPPER)
        .update('doc-token-v1:' + pa.sodDG1Hash).digest('hex')
    : null;

  const level = automaticDocumentAssurance
    ? 'document_active'
    : 'document_passive';
  const b = biometric.normalized;

  // БЕЗПЕКА ПЕРШ ЗА ВСЕ (raw SQL): суворо валідуємо КОЖНЕ значення, що
  // йде в SQL-рядок. Інʼєкція неможлива — лише hex/uuid/whitelist.
  if (!/^[0-9a-f]{64}$/.test(docToken) ||
      (legacyDocToken !== null && !/^[0-9a-f]{64}$/.test(legacyDocToken)) ||
      !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(contributorId) ||
      ![
        'passive_only',
        'chip_authentication_attested',
        'active_authentication',
        'chip_authentication_server',
      ]
        .includes(documentAssurance) ||
      !['document_active', 'document_passive'].includes(level)) {
    console.error('[verify/approve] bind params failed validation (fail-closed)');
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }

  try {
    if (protocolVersion === verificationPolicy.PROTOCOL_VERSION &&
        automaticDocumentAssurance) {
      const receipt = serverBiometrics;
      if (!receipt ||
          receipt.evaluationOnly !== false ||
          !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(receipt.requestId) ||
          !/^[a-zA-Z0-9_.-]{8,100}$/.test(receipt.policyVersion) ||
          !/^[0-9a-f]{64}$/.test(receipt.modelSetHash) ||
          !/^[0-9a-f]{64}$/.test(receipt.receiptDigest) ||
          !/^[0-9a-f]{64}$/.test(receipt.receiptSignature) ||
          !Number.isInteger(receipt.receiptTimestamp)) {
        console.error('[verify/approve] invalid self-hosted receipt (fail-closed)');
        return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
      }
      const activationInput = {
        documentToken: docToken,
        legacyDocumentToken: legacyDocToken,
        contributorId,
        requestId: receipt.requestId,
        policyVersion: receipt.policyVersion,
        modelSetHash: receipt.modelSetHash,
        receiptDigest: receipt.receiptDigest,
        receiptSignature: receipt.receiptSignature,
        serviceTimestamp: receipt.receiptTimestamp,
        protocolVersion,
        documentAssurance,
      };
      const outcome = documentAssurance === 'chip_authentication_server'
        ? await verificationStore.activateSelfHostedCAV7({
            ...activationInput,
            attestKeyId: req.headers['x-attest-key'],
            documentChallengeId: documentAuthenticationChallengeId,
            dg14Hash,
          })
        : await verificationStore.activateSelfHostedV7(activationInput);
      if (outcome === 'banned') {
        return res.status(403).json({ error: 'Цей документ заблоковано за порушення правил спільноти.' });
      }
      if (outcome === 'duplicate') {
        return res.status(409).json({ error: 'Цей документ уже використано для верифікації іншого акаунта.' });
      }
      if (outcome === 'contributor_conflict' || outcome === 'conflict') {
        return res.status(409).json({ error: 'Для цього акаунта або документа вже є інша активна верифікація.' });
      }
      if (outcome === 'already_verified') {
        return res.status(409).json({ error: 'Цей акаунт уже верифіковано.' });
      }
      if (outcome !== 'verified') {
        console.error('[verify/approve] activate_self_hosted_verified_id_v7_rotating → ', outcome);
        return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
      }

      console.log(`[verify/approve] ${contributorId.slice(0,8)}… status=verified ` +
        `level=strong pa=passed document_assurance=${documentAssurance} provider=self_hosted_v2`);
      try { for (const key of rlKeysFor(contributorId, req)) await rlReset(key); }
      catch (e) { console.error('[verify/approve] rl_reset:', e.message); }
      if (session) {
        const s = getVerifySession(session);
        if (s && s.contributorId === contributorId) s.status = 'verified';
      }
      return res.json({
        ok: true,
        status: 'verified',
        reviewRequired: false,
        verified: true,
        level: 'strong',
        passiveAuthentication: pa.status,
      });
    }

    // ОДНА транзакційна функція резервує document token у review-черзі,
    // перевіряє ban/duplicate і НЕ змінює contributors.verified.
    const outcome = await verificationStore.submitReviewV7({
      documentToken: docToken,
      legacyDocumentToken: legacyDocToken,
      contributorId,
      faceModel: b.faceModel,
      faceModelVersion: b.faceModelVersion,
      faceScore: b.faceScore,
      faceThreshold: b.faceThreshold,
      faceSampleCount: b.faceSampleCount,
      faceContinuityScore: b.faceContinuityScore,
      livenessFrameCount: b.livenessFrameCount,
      livenessDurationMs: b.livenessDurationMs,
      protocolVersion: b.protocolVersion,
      documentAssurance,
    });

    if (outcome === 'banned') {
      console.warn(`[verify/approve] BANNED DOC ${contributorId.slice(0,8)}…`);
      return res.status(403).json({ error: 'Цей документ заблоковано за порушення правил спільноти.' });
    }
    if (outcome === 'duplicate') {
      console.warn(`[verify/approve] DUPLICATE DOC ${contributorId.slice(0,8)}…`);
      return res.status(409).json({ error: 'Цей документ уже використано для верифікації іншого акаунта.' });
    }
    if (outcome === 'contributor_conflict' || outcome === 'conflict') {
      return res.status(409).json({ error: 'Для цього акаунта вже є активна заявка на перевірку.' });
    }
    if (outcome === 'already_verified') {
      return res.status(409).json({ error: 'Цей акаунт уже верифіковано.' });
    }
    if (outcome !== 'pending') {
      console.error('[verify/approve] submit_verification_review_v7_rotating → ', outcome);
      return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
    }

    console.log(`[verify/approve] ${contributorId.slice(0,8)}… status=pending_review level=${level} pa=passed alg=${pa.algorithm || '-'} live=${liveness} issuer_ok=1`);
    // PA + device pre-check прийняті — чистий старт лічильника спроб.
    try { for (const key of rlKeysFor(contributorId, req)) await rlReset(key); }
    catch (e) { console.error('[verify/approve] rl_reset:', e.message); }
    // Якщо флоу стартував з десктопа через QR — повідомити його модалку.
    if (session) {
      const s = getVerifySession(session);
      if (s && s.contributorId === contributorId) s.status = 'pending_review';
    }
    return res.json({
      ok: true,
      status: 'pending_review',
      reviewRequired: true,
      verified: false,
      level,
      passiveAuthentication: pa.status,
    });
  } catch (e) {
    console.error('[verify/approve] submit_verification_review_v7_rotating (run_sql):', e.message);
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }
});

//  СПОВІЩЕННЯ (push)
//
//  1. Застосунок реєструє токен пристрою:  POST /auth/device-token
//  2. Hasura event trigger стукає сюди:    POST /internal/hasura-event
//     (захищено секретом HASURA_EVENT_SECRET — назовні цей шлях закритий)
//  3. Ми пишемо рядок у notifications і шлемо push на всі пристрої людини.
//
//  Приватність: у тексті push — лише те, що людина й так бачить
//  у застосунку. Жодних даних документа.
// ═══════════════════════════════════════════════════════════════════
const apns = require('./apns');
const EVENT_SECRET = process.env.HASURA_EVENT_SECRET || '';

// ── Реєстрація токена пристрою ─────────────────────────────────────
app.post('/auth/device-token', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const { token, platform, environment, kind } = req.body || {};
  if (!token || typeof token !== 'string' || token.length < 32) {
    return res.status(400).json({ error: 'Некоректний токен пристрою' });
  }

  try {
    await hasuraAdmin(
      `mutation($obj: device_tokens_insert_input!) {
         insert_device_tokens_one(object: $obj,
           on_conflict: {constraint: device_tokens_pkey,
                         update_columns: [contributor_id, platform, environment, kind, updated_at]}
         ) { token }
       }`,
      { obj: {
          token,
          contributor_id: contributorId,
          platform: platform === 'android' ? 'android' : 'ios',
          environment: environment === 'sandbox' ? 'sandbox' : 'production',
          kind: kind === 'voip' ? 'voip' : 'apns',
          updated_at: new Date().toISOString(),
      } }
    );
    return res.json({ ok: true });
  } catch (e) {
    console.error('[device-token]', e.message);
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});

// ── Вкладення чату: файли БЕЗ стиснення (до 25 МБ) ─────────────────
//  Великі файли не влазять у базу (data-URL), тому лежать на диску:
//  /app/uploads (docker-volume uploads_data), роздає nginx як /files/…
//  Імʼя — випадкові 32 hex-символи: вгадати посилання неможливо.
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/app/uploads';
const UPLOAD_MAX = 25 * 1024 * 1024;

app.post('/auth/upload', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const { name, data } = req.body || {};
  if (!data || typeof data !== 'string') {
    return res.status(400).json({ error: 'Порожній файл' });
  }

  const buf = decodeBase64Strict(data);
  if (!buf || buf.length === 0) {
    return res.status(400).json({ error: 'Файл не розкодувався' });
  }
  if (buf.length > UPLOAD_MAX) {
    return res.status(413).json({ error: 'Файл завеликий. Максимум — 25 МБ.' });
  }

  // The client-provided filename is never used to choose the stored extension.
  // Only a narrow, magic-byte-verified media allowlist is accepted.
  const uploadType = classifyUpload(buf);
  if (!uploadType) {
    return res.status(415).json({
      error: 'Непідтримуваний формат. Дозволені JPEG, PNG, GIF, WebP, HEIC, AVIF, MP4, MOV, M4A, WebM і PDF.',
    });
  }
  const fname = `${crypto.randomBytes(16).toString('hex')}.${uploadType.extension}`;

  try {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o750 });
    fs.writeFileSync(path.join(UPLOAD_DIR, fname), buf, { flag: 'wx', mode: 0o600 });
    await authSecurityStore.registerUpload({ filename: fname, contributorId });
  } catch (e) {
    try { fs.unlinkSync(path.join(UPLOAD_DIR, fname)); } catch (_) {}
    console.error('[upload]', e.message);
    return res.status(500).json({ error: 'Помилка сервера' });
  }

  const base = process.env.PUBLIC_APP_URL || 'https://ostrovua.online';
  console.log(`[upload] ${contributorId.slice(0, 8)}… accepted (${Math.round(buf.length / 1024)} КБ)`);
  return res.json({
    ok: true,
    url: `${base}/files/${fname}`,
    mime: uploadType.mime,
    disposition: uploadType.disposition,
  });
});

function canonicalUploadPath(filename) {
  if (!/^[0-9a-f]{32}\.(?:jpg|png|gif|webp|heic|avif|mp4|mov|m4a|webm|pdf)$/.test(filename || '')) {
    throw new Error('upload_filename_invalid');
  }
  const root = path.resolve(UPLOAD_DIR);
  const candidate = path.resolve(root, filename);
  if (path.dirname(candidate) !== root) throw new Error('upload_path_invalid');
  return candidate;
}

async function removeDeletionFiles(entries) {
  let pending = 0;
  for (const entry of entries) {
    try {
      const filePath = canonicalUploadPath(entry.filename);
      try {
        fs.unlinkSync(filePath);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      await authSecurityStore.markDeletionFileRemoved(entry);
    } catch (error) {
      pending += 1;
      console.error('[account-delete-file]', error.message);
    }
  }
  return pending;
}

let deletionWorkerRunning = false;
async function runDeletionFileWorker() {
  if (deletionWorkerRunning) return;
  deletionWorkerRunning = true;
  try {
    const pending = await authSecurityStore.pendingDeletionFiles(100);
    await removeDeletionFiles(pending);
  } catch (error) {
    // The durable DB queue remains pending and a later pass retries.
    console.error('[account-delete-worker]', error.message);
  } finally {
    deletionWorkerRunning = false;
  }
}

app.delete('/auth/account', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;
  if (req.get('x-account-deletion-confirmation') !== 'DELETE') {
    return res.status(400).json({ error: 'Потрібне явне підтвердження видалення' });
  }
  const authTime = Number(req.authPayload?.auth_time || 0);
  if (!authTime || Date.now() / 1000 - authTime > 30 * 60) {
    return res.status(428).json({
      error: 'Для видалення акаунта потрібно повторно увійти не більше 30 хвилин тому.',
      code: 'REAUTHENTICATION_REQUIRED',
    });
  }

  try {
    const receiptId = crypto.randomUUID();
    const deletion = await authSecurityStore.deleteAccount({
      contributorId,
      receiptId,
    });
    const entries = deletion.files.map((filename) => ({ receiptId, filename }));
    const filesPendingDeletion = await removeDeletionFiles(entries);
    return res.json({
      ok: true,
      deletionReceipt: receiptId,
      filesPendingDeletion,
    });
  } catch (error) {
    console.error('[account-delete]', error.message);
    return res.status(500).json({ error: 'Не вдалося завершити видалення акаунта' });
  }
});

// ── Дзвінки: тимчасові TURN-креденшели (coturn, use-auth-secret) ────
//  username = "<unix-час протухання>:<contributor_id>",
//  credential = HMAC-SHA1(username, TURN_STATIC_SECRET). TTL 6 годин.
app.get('/auth/turn-credentials', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const secret = process.env.TURN_STATIC_SECRET || '';
  if (!secret) return res.status(503).json({ error: 'TURN не налаштовано' });

  const ttl = 6 * 3600;
  const username = `${Math.floor(Date.now() / 1000) + ttl}:${contributorId}`;
  const credential = crypto.createHmac('sha1', secret).update(username).digest('base64');

  return res.json({
    username,
    credential,
    ttl,
    urls: [
      'stun:62.238.27.61:3478',
      'turn:62.238.27.61:3478?transport=udp',
      'turn:62.238.27.61:3478?transport=tcp',
    ],
  });
});

// ── Групові дзвінки: токен доступу до LiveKit (медіасервер) ────────
//  JWT HS256 за специфікацією LiveKit — без зайвих залежностей.
//  Пускаємо ЛИШЕ учасника кімнати чату; identity = contributor_id.
app.get('/auth/livekit-token', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const apiKey = process.env.LIVEKIT_API_KEY || '';
  const apiSecret = process.env.LIVEKIT_API_SECRET || '';
  if (!apiKey || !apiSecret) {
    return res.status(503).json({ error: 'LiveKit не налаштовано' });
  }

  const roomId = String(req.query.room || '');
  if (!roomId) return res.status(400).json({ error: 'room обовʼязковий' });

  try {
    // Доступ: учасник кімнати, системна кімната АБО запрошений гість
    const d = await hasuraAdmin(
      `query($room: uuid!, $me: uuid!) {
         chat_rooms_by_pk(id: $room) {
           kind
           members(where: {contributor_id: {_eq: $me}}) { contributor_id }
         }
         call_guests(where: {room_id: {_eq: $room}, contributor_id: {_eq: $me}}) { contributor_id }
         contributors_by_pk(id: $me) { name }
       }`,
      { room: roomId, me: contributorId }
    );
    const room = d.chat_rooms_by_pk;
    if (!room) return res.status(404).json({ error: 'Кімнату не знайдено' });
    const isGuest = (d.call_guests || []).length > 0;
    if (room.kind !== 'system' && (room.members || []).length === 0 && !isGuest) {
      return res.status(403).json({ error: 'Ти не учасник цієї кімнати' });
    }
    const name = d.contributors_by_pk?.name || 'Учасник';

    const now = Math.floor(Date.now() / 1000);
    const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      iss: apiKey,
      sub: contributorId,
      name,
      nbf: now - 10,
      exp: now + 6 * 3600,
      video: {
        room: roomId,
        roomJoin: true,
        canPublish: true,
        canSubscribe: true,
      },
    };
    const unsigned = `${b64(header)}.${b64(payload)}`;
    const signature = crypto.createHmac('sha256', apiSecret).update(unsigned).digest('base64url');

    return res.json({
      url: process.env.LIVEKIT_URL || 'wss://ostrovua.online/livekit',
      token: `${unsigned}.${signature}`,
    });
  } catch (e) {
    console.error('[livekit-token]', e.message);
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});

// ── Групові дзвінки: запросити людину в кімнату ────────────────────
//  Тому, кого кличуть, летить push; тап відкриває застосунок,
//  у чаті вже висить банер «Приєднатись».
app.post('/auth/call-invite', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const { room_id, invitee_id } = req.body || {};
  if (!room_id || !invitee_id) {
    return res.status(400).json({ error: 'room_id та invitee_id обовʼязкові' });
  }

  try {
    const d = await hasuraAdmin(
      `query($room: uuid!, $me: uuid!) {
         chat_rooms_by_pk(id: $room) {
           title kind
           members(where: {contributor_id: {_eq: $me}}) { contributor_id }
         }
         contributors_by_pk(id: $me) { name }
       }`,
      { room: room_id, me: contributorId }
    );
    const room = d.chat_rooms_by_pk;
    if (!room) return res.status(404).json({ error: 'Кімнату не знайдено' });
    if (room.kind !== 'system' && (room.members || []).length === 0) {
      return res.status(403).json({ error: 'Ти не учасник цієї кімнати' });
    }

    const inviterName = d.contributors_by_pk?.name || 'Учасник';

    // Гостьовий пропуск: запрошений зможе зайти в LiveKit-кімнату,
    // навіть якщо він не учасник цього чату
    await hasuraAdmin(
      `mutation($obj: call_guests_insert_input!) {
         insert_call_guests_one(object: $obj,
           on_conflict: {constraint: call_guests_pkey, update_columns: [created_at]}
         ) { room_id }
       }`,
      { obj: { room_id, contributor_id: invitee_id, created_at: new Date().toISOString() } }
    ).catch((e) => console.warn('[call-invite:guest]', e.message));

    await notify(invitee_id, {
      kind: 'chat_message',
      title: room.title,
      body: `🎙 ${inviterName} запрошує тебе до дзвінка`,
      targetId: room_id,
      saveHistory: false,
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error('[call-invite]', e.message);
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Відписатися (вихід з акаунта)
app.post('/auth/device-token/remove', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token обовʼязковий' });

  try {
    await hasuraAdmin(
      `mutation($t: String!) { delete_device_tokens_by_pk(token: $t) { token } }`,
      { t: token }
    );
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});

// ── Надіслати сповіщення людині (запис + push) ─────────────────────
//  saveHistory: false — лише push, БЕЗ рядка в notifications.
//  Повідомлення чату не мають засмічувати розділ «Сповіщення» —
//  там лише системне: внески на перевірку, рішення, голосування.
async function notify(contributorId, { kind, title, body, targetId, saveHistory = true }) {
  if (!contributorId) return;

  // 1. Історія в застосунку — навіть якщо push не дійде
  if (saveHistory) {
    try {
      await hasuraAdmin(
        `mutation($obj: notifications_insert_input!) {
           insert_notifications_one(object: $obj) { id }
         }`,
        { obj: { contributor_id: contributorId, kind, title, body: body || '', target_id: targetId || null } }
      );
    } catch (e) {
      console.error('[notify:db]', e.message);
    }
  }

  // 2. Push на всі пристрої людини
  try {
    const data = await hasuraAdmin(
      `query($id: uuid!) {
         device_tokens(where: {contributor_id: {_eq: $id}}) { token environment }
         notifications_aggregate(where: {contributor_id: {_eq: $id}, is_read: {_eq: false}}) {
           aggregate { count }
         }
       }`,
      { id: contributorId }
    );

    const devices = data.device_tokens || [];
    const badge = data.notifications_aggregate?.aggregate?.count ?? undefined;

    if (devices.length === 0) {
      console.log(`[push] ${kind}: у людини немає жодного пристрою`);
      return;
    }

    for (const { token, environment } of devices) {
      // Кожен токен йде у СВІЙ хост APNs: sandbox-токен (білд з Xcode)
      // у production-хост Apple відхиляє як BadDeviceToken.
      const result = await apns.sendPush(token, {
        title, body, badge, environment,
        data: { target_id: targetId || null, kind },
      });

      console.log(
        `[push] ${kind} ` +
        `${result.ok ? 'OK' : 'FAIL'} ` +
        `status=${result.status ?? '-'} reason=${result.reason ?? '-'} env=${environment || process.env.APNS_ENV}`
      );

      // Токен протух — прибираємо, щоб не слати в нікуди
      if (!result.ok && (result.reason === 'BadDeviceToken' || result.reason === 'Unregistered')) {
        console.warn(`[push] stale token removed (${result.reason})`);
        await hasuraAdmin(
          `mutation($t: String!) { delete_device_tokens_by_pk(token: $t) { token } }`,
          { t: token }
        ).catch(() => {});
      }
    }
  } catch (e) {
    console.error('[notify:push]', e.message);
  }
}

// ── Події з Hasura ─────────────────────────────────────────────────
app.post('/internal/hasura-event', async (req, res) => {
  if (!EVENT_SECRET || req.headers['x-event-secret'] !== EVENT_SECRET) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const name = req.body?.trigger?.name;
  const row  = req.body?.event?.data?.new;
  if (!row) return res.json({ ok: true });

  try {
    // 1. Внесок призначено координатору на перевірку
    if (name === 'on_review_assigned') {
      const d = await hasuraAdmin(
        `query($r: uuid!) {
           participation_records_by_pk(id: $r) {
             title type
             contributor { name }
           }
         }`,
        { r: row.record_id }
      );
      const rec = d.participation_records_by_pk;
      await notify(row.coordinator_id, {
        kind: 'review_assigned',
        title: 'Новий внесок на перевірку',
        body: `${rec?.contributor?.name || 'Учасник'}: ${rec?.title || 'внесок'} — 72 години на рішення`,
        targetId: row.record_id,
      });
    }

    // 2. По внеску ухвалено рішення → автору
    if (name === 'on_review_decided') {
      const d = await hasuraAdmin(
        `query($r: uuid!) {
           participation_records_by_pk(id: $r) { title contributor_id }
         }`,
        { r: row.record_id }
      );
      const rec = d.participation_records_by_pk;

      const titles = {
        accepted: 'Внесок підтверджено',
        partially_accepted: 'Внесок підтверджено частково',
        needs_more_info: 'Потрібні деталі щодо внеску',
        rejected: 'Внесок відхилено',
      };

      await notify(rec?.contributor_id, {
        kind: 'review_decided',
        title: titles[row.decision] || 'Рішення щодо внеску',
        body: row.comment ? String(row.comment).slice(0, 180) : (rec?.title || ''),
        targetId: row.record_id,
      });
    }

    // 3. Нове повідомлення в групі → учасникам (крім автора)
    if (name === 'on_chat_message') {
      const d = await hasuraAdmin(
        `query($room: uuid!) {
           chat_rooms_by_pk(id: $room) {
             title kind
             members { contributor_id }
           }
         }`,
        { room: row.room_id }
      );
      const room = d.chat_rooms_by_pk;

      // Системні кімнати не спамимо — там усі
      if (room && room.kind !== 'system') {
        const author = await hasuraAdmin(
          `query($id: uuid!) { contributors_by_pk(id: $id) { name } }`,
          { id: row.contributor_id }
        );
        const authorName = author.contributors_by_pk?.name || 'Учасник';

        // Без тексту (фото/файл/голосове/список) — зрозумілий підпис у push
        const attachLabel = {
          image: '📷 Фото',
          album: '📷 Фотоальбом',
          file: '📎 Файл',
          voice: '🎤 Голосове повідомлення',
          video_note: '📹 Відео-кружок',
          checklist: '✅ Список задач',
        }[row.attachment_type] || '';
        const text = String(row.text || '').slice(0, 140) || attachLabel || '…';

        for (const m of room.members || []) {
          if (m.contributor_id === row.contributor_id) continue;

          // Особистий чат: у заголовку — ХТО написав.
          // (Назва кімнати там — імʼя співрозмовника, тобто самого отримувача.)
          const isDirect = room.kind === 'direct';

          await notify(m.contributor_id, {
            kind: 'chat_message',
            title: isDirect ? authorName : room.title,
            body: isDirect ? text : `${authorName}: ${text}`,
            targetId: row.room_id,
            saveHistory: false,   // чат — лише push, без сліду в «Сповіщеннях»
          });
        }
      }
    }

    // 4. Вхідний дзвінок → VoIP-push (CallKit: телефон ДЗВОНИТЬ навіть
    //    закритим). Якщо voip-токена немає (старий білд) — звичайний push.
    if (name === 'on_call_created') {
      const caller = await hasuraAdmin(
        `query($id: uuid!) { contributors_by_pk(id: $id) { name } }`,
        { id: row.caller_id }
      );
      const callerName = caller.contributors_by_pk?.name || 'Учасник';

      const tok = await hasuraAdmin(
        `query($id: uuid!) {
           device_tokens(where: {contributor_id: {_eq: $id}}) { token environment kind }
         }`,
        { id: row.callee_id }
      );
      const voipDevices = (tok.device_tokens || []).filter((d) => d.kind === 'voip');

      if (voipDevices.length > 0) {
        for (const device of voipDevices) {
          const result = await apns.sendVoipPush(device.token, {
            environment: device.environment,
            payload: {
              type: 'incoming_call',
              call_id: row.id,
              caller_id: row.caller_id,
              caller_name: callerName,
              kind: row.kind,
              room_id: row.room_id,
            },
          });
          console.log(
            `[voip] call → ${device.token.slice(0, 10)}… ` +
            `${result.ok ? 'OK' : 'FAIL'} status=${result.status} reason=${result.reason ?? '-'}`
          );
          if (!result.ok && (result.reason === 'BadDeviceToken' || result.reason === 'Unregistered')) {
            await hasuraAdmin(
              `mutation($t: String!) { delete_device_tokens_by_pk(token: $t) { token } }`,
              { t: device.token }
            ).catch(() => {});
          }
        }
      } else {
        await notify(row.callee_id, {
          kind: 'chat_message',
          title: callerName,
          body: row.kind === 'video' ? '📹 Вхідний відеодзвінок' : '📞 Вхідний дзвінок',
          targetId: row.room_id,
          saveHistory: false,
        });
      }
    }

    // 5. Груповий голосовий чат розпочато → push учасникам кімнати
    if (name === 'on_group_call_created') {
      const d = await hasuraAdmin(
        `query($room: uuid!, $starter: uuid!) {
           chat_rooms_by_pk(id: $room) { title kind members { contributor_id } }
           contributors_by_pk(id: $starter) { name }
         }`,
        { room: row.room_id, starter: row.started_by }
      );
      const room = d.chat_rooms_by_pk;
      const starterName = d.contributors_by_pk?.name || 'Учасник';

      if (room && room.kind !== 'system') {
        for (const m of room.members || []) {
          if (m.contributor_id === row.started_by) continue;
          await notify(m.contributor_id, {
            kind: 'chat_message',
            title: room.title,
            body: `🎙 ${starterName} розпочав голосовий чат`,
            targetId: row.room_id,
            saveHistory: false,
          });
        }
      }
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('[hasura-event]', e.message);
    return res.status(500).json({ error: 'event failed' });
  }
});

app.use((_, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`[auth] :${PORT}  Hasura: ${HASURA_URL}`);
  console.log(`[auth] Google:   ${GOOGLE_CLIENT_ID   ? '✓' : '✗ not configured'}`);
  console.log(`[auth] GitHub:   ${GITHUB_CLIENT_ID   ? '✓' : '✗ not configured'}`);
  console.log(`[auth] Telegram: ${TELEGRAM_BOT_TOKEN ? '✓' : '✗ not configured'}`);
  const firstDeletionPass = setTimeout(runDeletionFileWorker, 1_000);
  firstDeletionPass.unref?.();
  const deletionInterval = setInterval(runDeletionFileWorker, 5 * 60_000);
  deletionInterval.unref?.();
});
