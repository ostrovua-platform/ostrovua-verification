-- ═══════════════════════════════════════════════════════════════════
--  Схема бази, повʼязана з верифікацією (PostgreSQL + Hasura).
--  Дослівні DDL з продакшн-міграцій (apply_attest_keys.sh,
--  apply_document_tokens.sh). Персональних полів документа НЕМАЄ.
-- ═══════════════════════════════════════════════════════════════════

-- Учасник. Верифікація лишає ЛИШЕ статус і типізований рівень довіри.
-- Полів номера/імені/фото з паспорта НЕ існує.
-- (contributors створюється в основній міграції; тут — колонки верифікації)
ALTER TABLE contributors ADD COLUMN IF NOT EXISTS verified            BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE contributors ADD COLUMN IF NOT EXISTS verified_at         TIMESTAMPTZ;
ALTER TABLE contributors ADD COLUMN IF NOT EXISTS verification_method TEXT;
ALTER TABLE contributors ADD COLUMN IF NOT EXISTS banned              BOOLEAN NOT NULL DEFAULT FALSE;

-- Типізований рівень доказовості (authorization boundary, аудит P0-01).
-- Protocol v7 записує strong лише через v7 activation function після
-- server-side AA + biometric receipt. Passive/attested-CA створює review.
ALTER TABLE contributors ADD COLUMN IF NOT EXISTS identity_assurance TEXT
    CHECK (identity_assurance IN ('strong') OR identity_assurance IS NULL);

-- Ключі App Attest пристроїв. Публічний ключ + монотонний counter.
CREATE TABLE IF NOT EXISTS attest_keys (
    key_id         TEXT PRIMARY KEY,
    contributor_id UUID NOT NULL REFERENCES contributors(id) ON DELETE CASCADE,
    public_key_pem TEXT NOT NULL,
    counter        BIGINT NOT NULL DEFAULT 0,          -- CAS: приймається лише зростання
    environment    TEXT NOT NULL DEFAULT 'production',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_attest_contributor ON attest_keys(contributor_id);

-- Токени документів: «1 паспорт = 1 акаунт» + бан документа.
-- token = HMAC(pepper, держ. хеш DG1 із SOD). НЕ номер паспорта.
CREATE TABLE IF NOT EXISTS document_tokens (
    token             TEXT PRIMARY KEY,                -- серіалізує гонку клейму
    contributor_id    UUID REFERENCES contributors(id) ON DELETE SET NULL,
    status            TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active','banned')),
    first_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_verified_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Один акаунт ↔ максимум один активний документ.
CREATE UNIQUE INDEX IF NOT EXISTS idx_doc_token_contributor
    ON document_tokens(contributor_id) WHERE contributor_id IS NOT NULL;

-- ── Атомарна привʼязка (аудит P0-02), як робить обробник ────────────
-- INSERT … ON CONFLICT (token) DO UPDATE … WHERE:
--   оновлюємо contributor_id ЛИШЕ якщо рядок ще не привʼязаний або вже
--   наш, і статус active. Дві одночасні спроби різних акаунтів для
--   одного документа серіалізуються на PK token: перший привʼязує,
--   другий не проходить WHERE (0 рядків) → 409. Забанений (status!=active)
--   → WHERE хибний → лишається забаненим.
--
--   INSERT INTO document_tokens(token, contributor_id, status, last_verified_at)
--   VALUES ($token, $me, 'active', now())
--   ON CONFLICT (token) DO UPDATE
--     SET contributor_id = EXCLUDED.contributor_id, last_verified_at = now()
--     WHERE (document_tokens.contributor_id IS NULL
--            OR document_tokens.contributor_id = $me)
--       AND document_tokens.status = 'active'
--   RETURNING token, contributor_id;   -- нема рядка → зайнятий/забанений

-- Challenge App Attest — В ПАМʼЯТІ auth-процесу (TTL 5 хв, одноразові,
-- ліміт на акаунт і глобальний). У базі не зберігаються за задумом:
-- одноразовий секрет короткого життя, не персональні дані.

-- Актуальні v7 assurance/review/receipt та fail-closed limiter:
--   Server/migrations/20260724_document_assurance_v7.sql
--   Server/migrations/20260724_verification_rate_limit_fail_closed.sql
