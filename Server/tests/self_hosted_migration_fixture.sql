\set ON_ERROR_STOP on

CREATE TABLE contributors (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    verification_method TEXT,
    identity_assurance TEXT
);
CREATE TABLE document_tokens (
    token TEXT PRIMARY KEY,
    contributor_id UUID REFERENCES contributors(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('active','banned')),
    first_verified_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_doc_token_contributor
    ON document_tokens(contributor_id) WHERE contributor_id IS NOT NULL;
CREATE TABLE verification_requests (
    id BIGSERIAL PRIMARY KEY,
    contributor_id UUID NOT NULL REFERENCES contributors(id) ON DELETE CASCADE,
    document_token TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','cancelled')),
    review_reason TEXT,
    evidence_protocol SMALLINT NOT NULL DEFAULT 5,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_verification_request_active_contributor
    ON verification_requests(contributor_id) WHERE status IN ('pending','approved');
CREATE UNIQUE INDEX uq_verification_request_active_document
    ON verification_requests(document_token) WHERE status IN ('pending','approved');
CREATE TABLE verify_rate_limit (
    rl_key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    tier INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO contributors(id, status) VALUES
    ('00000000-0000-4000-8000-000000000001', 'active'),
    ('00000000-0000-4000-8000-000000000002', 'active');

\ir ../migrations/20260723_self_hosted_verified_id.sql
\ir ../migrations/20260723_verification_rate_limit_first_attempts.sql
\ir ../migrations/20260724_document_assurance_v7.sql
\ir ../migrations/20260724_verification_rate_limit_fail_closed.sql

DO $$
DECLARE
    v_result TEXT;
BEGIN
    SELECT activate_self_hosted_verified_id_v7_rotating(
        repeat('f', 64), NULL,
        '00000000-0000-4000-8000-000000000001',
        '30000000-0000-4000-8000-000000000001',
        'ostrovua-self-hosted-2026-07-v1', repeat('b', 64),
        repeat('c', 64), repeat('d', 64), EXTRACT(EPOCH FROM NOW())::BIGINT,
        6, 'active_authentication'
    ) INTO v_result;
    IF v_result <> 'invalid' THEN RAISE EXCEPTION 'protocol v6 was not rejected'; END IF;

    SELECT activate_self_hosted_verified_id_v7_rotating(
        repeat('a', 64), NULL,
        '00000000-0000-4000-8000-000000000001',
        '10000000-0000-4000-8000-000000000001',
        'ostrovua-self-hosted-2026-07-v1', repeat('b', 64),
        repeat('c', 64), repeat('d', 64), EXTRACT(EPOCH FROM NOW())::BIGINT,
        7, 'active_authentication'
    ) INTO v_result;
    IF v_result <> 'verified' THEN RAISE EXCEPTION 'expected verified, got %', v_result; END IF;
    IF NOT (SELECT verified FROM contributors WHERE id='00000000-0000-4000-8000-000000000001') THEN
        RAISE EXCEPTION 'contributor was not activated';
    END IF;
    IF (SELECT count(*) FROM verification_receipts) <> 1 THEN
        RAISE EXCEPTION 'receipt missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM verification_receipts
         WHERE evidence_protocol = 7
           AND document_assurance = 'active_authentication'
    ) THEN
        RAISE EXCEPTION 'v7 document assurance missing';
    END IF;

    SELECT activate_self_hosted_verified_id_v7_rotating(
        repeat('a', 64), NULL,
        '00000000-0000-4000-8000-000000000002',
        '20000000-0000-4000-8000-000000000001',
        'ostrovua-self-hosted-2026-07-v1', repeat('b', 64),
        repeat('e', 64), repeat('f', 64), EXTRACT(EPOCH FROM NOW())::BIGINT,
        7, 'active_authentication'
    ) INTO v_result;
    IF v_result <> 'duplicate' THEN RAISE EXCEPTION 'expected duplicate, got %', v_result; END IF;
    IF (SELECT verified FROM contributors WHERE id='00000000-0000-4000-8000-000000000002') THEN
        RAISE EXCEPTION 'duplicate document activated second account';
    END IF;
END;
$$;

DO $$
DECLARE
    v_locked BOOLEAN;
    v_until TIMESTAMPTZ;
    v_tier INTEGER;
    v_attempt INTEGER;
BEGIN
    FOR v_attempt IN 1..9 LOOP
        SELECT is_locked, until, cur_tier
          INTO v_locked, v_until, v_tier
          FROM rl_touch('acct:00000000-0000-4000-8000-000000000001');
        IF v_locked THEN
            RAISE EXCEPTION 'rate limiter locked before the tenth attempt';
        END IF;
    END LOOP;

    SELECT is_locked, until, cur_tier
      INTO v_locked, v_until, v_tier
      FROM rl_touch('acct:00000000-0000-4000-8000-000000000001');
    IF NOT v_locked OR v_tier <> 1 OR v_until IS NULL THEN
        RAISE EXCEPTION 'tenth attempt did not create first-tier lock';
    END IF;

    SELECT is_locked, until, cur_tier
      INTO v_locked, v_until, v_tier
      FROM rl_check('acct:00000000-0000-4000-8000-000000000001');
    IF NOT v_locked OR v_tier <> 1 THEN
        RAISE EXCEPTION 'non-incrementing lock check did not observe the lock';
    END IF;

    PERFORM rl_reset('acct:00000000-0000-4000-8000-000000000001');
    SELECT is_locked, until, cur_tier
      INTO v_locked, v_until, v_tier
      FROM rl_check('acct:00000000-0000-4000-8000-000000000001');
    IF v_locked OR v_tier <> 0 THEN
        RAISE EXCEPTION 'rate limiter reset failed';
    END IF;

    BEGIN
        PERFORM * FROM rl_check('invalid');
        RAISE EXCEPTION 'invalid rate-limit key was accepted';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM = 'invalid rate-limit key was accepted' THEN
                RAISE;
            END IF;
    END;
END;
$$;

SELECT 'self_hosted_migration_fixture: PASS';
