BEGIN;

-- Мінімальний незмінний audit receipt. Тут немає MRZ, фото, face embedding
-- або біометричних score: лише факт успішної політики та HMAC-підписана
-- квитанція внутрішнього worker'а.
CREATE TABLE IF NOT EXISTS verification_receipts (
    request_id          UUID PRIMARY KEY,
    contributor_id      UUID NOT NULL REFERENCES contributors(id) ON DELETE CASCADE,
    document_token      TEXT NOT NULL CHECK (document_token ~ '^[0-9a-f]{64}$'),
    provider            TEXT NOT NULL CHECK (provider = 'self_hosted_v1'),
    result              TEXT NOT NULL CHECK (result = 'passed'),
    policy_version      TEXT NOT NULL CHECK (policy_version ~ '^[a-zA-Z0-9_.-]{8,100}$'),
    model_set_hash      TEXT NOT NULL CHECK (model_set_hash ~ '^[0-9a-f]{64}$'),
    receipt_digest      TEXT NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    receipt_signature   TEXT NOT NULL CHECK (receipt_signature ~ '^[0-9a-f]{64}$'),
    service_timestamp   BIGINT NOT NULL,
    evidence_protocol   SMALLINT NOT NULL CHECK (evidence_protocol = 6),
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_verification_receipts_contributor
    ON verification_receipts(contributor_id, verified_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_verification_receipts_document
    ON verification_receipts(document_token);

REVOKE ALL ON verification_receipts FROM PUBLIC;

CREATE OR REPLACE FUNCTION activate_self_hosted_verified_id_rotating(
    p_document_token         TEXT,
    p_legacy_document_token  TEXT,
    p_contributor_id         UUID,
    p_request_id             UUID,
    p_policy_version         TEXT,
    p_model_set_hash         TEXT,
    p_receipt_digest         TEXT,
    p_receipt_signature      TEXT,
    p_service_timestamp      BIGINT,
    p_evidence_protocol      INTEGER
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_lock_key TEXT;
    v_candidate_token TEXT;
    v_doc_owner UUID;
    v_doc_status TEXT;
    v_contributor_status TEXT;
    v_contributor_banned BOOLEAN;
    v_contributor_verified BOOLEAN;
    v_other_document TEXT;
    v_request_owner UUID;
BEGIN
    IF p_document_token !~ '^[0-9a-f]{64}$'
       OR (p_legacy_document_token IS NOT NULL
           AND (p_legacy_document_token !~ '^[0-9a-f]{64}$'
                OR p_legacy_document_token = p_document_token))
       OR p_policy_version !~ '^[a-zA-Z0-9_.-]{8,100}$'
       OR p_model_set_hash !~ '^[0-9a-f]{64}$'
       OR p_receipt_digest !~ '^[0-9a-f]{64}$'
       OR p_receipt_signature !~ '^[0-9a-f]{64}$'
       OR p_service_timestamp < EXTRACT(EPOCH FROM NOW())::BIGINT - 300
       OR p_service_timestamp > EXTRACT(EPOCH FROM NOW())::BIGINT + 300
       OR p_evidence_protocol <> 6 THEN
        RETURN 'invalid';
    END IF;

    -- Один глобальний порядок усіх advisory-lock прибирає deadlock між
    -- pepper rotation, двома документами акаунта і двома акаунтами документа.
    FOR v_lock_key IN
        SELECT DISTINCT key
          FROM unnest(ARRAY[
              'contributor:' || p_contributor_id::TEXT,
              'document:' || p_document_token,
              CASE WHEN p_legacy_document_token IS NULL THEN NULL
                   ELSE 'document:' || p_legacy_document_token END
          ]) AS locks(key)
         WHERE key IS NOT NULL
         ORDER BY key
    LOOP
        PERFORM pg_advisory_xact_lock(hashtextextended(v_lock_key, 0));
    END LOOP;

    SELECT status, banned, verified
      INTO v_contributor_status, v_contributor_banned, v_contributor_verified
      FROM contributors WHERE id = p_contributor_id FOR UPDATE;
    IF NOT FOUND OR v_contributor_status <> 'active' OR v_contributor_banned THEN
        RETURN 'account_invalid';
    END IF;
    IF v_contributor_verified THEN
        RETURN 'already_verified';
    END IF;

    FOR v_candidate_token, v_doc_owner, v_doc_status IN
        SELECT token, contributor_id, status
          FROM document_tokens
         WHERE token = ANY(ARRAY[p_document_token, p_legacy_document_token])
         ORDER BY token
         FOR UPDATE
    LOOP
        IF v_doc_status = 'banned' THEN RETURN 'banned'; END IF;
        IF v_doc_owner IS NOT NULL AND v_doc_owner <> p_contributor_id THEN
            RETURN 'duplicate';
        END IF;
    END LOOP;

    SELECT token INTO v_other_document
      FROM document_tokens
     WHERE contributor_id = p_contributor_id
       AND token <> p_document_token
       AND (p_legacy_document_token IS NULL OR token <> p_legacy_document_token)
     LIMIT 1 FOR UPDATE;
    IF FOUND THEN RETURN 'contributor_conflict'; END IF;

    -- Чужа pending/approved заявка на будь-яке покоління токена блокує claim.
    SELECT contributor_id INTO v_request_owner
      FROM verification_requests
     WHERE document_token = ANY(ARRAY[p_document_token, p_legacy_document_token])
       AND status IN ('pending','approved')
     ORDER BY id DESC LIMIT 1 FOR UPDATE;
    IF FOUND AND v_request_owner <> p_contributor_id THEN RETURN 'duplicate'; END IF;

    -- Успішна ротація: після перевірки обох поколінь канонічним стає лише
    -- активний токен. Старий active claim видаляється в тій самій транзакції.
    IF p_legacy_document_token IS NOT NULL THEN
        DELETE FROM document_tokens
         WHERE token = p_legacy_document_token
           AND status = 'active'
           AND (contributor_id IS NULL OR contributor_id = p_contributor_id);
        UPDATE verification_requests
           SET document_token = p_document_token, updated_at = NOW()
         WHERE contributor_id = p_contributor_id
           AND document_token = p_legacy_document_token
           AND status IN ('pending','approved');
    END IF;

    INSERT INTO document_tokens(token, contributor_id, status, first_verified_at, last_verified_at)
    VALUES (p_document_token, p_contributor_id, 'active', NOW(), NOW())
    ON CONFLICT (token) DO UPDATE
       SET contributor_id = EXCLUDED.contributor_id,
           last_verified_at = NOW()
     WHERE document_tokens.status = 'active'
       AND (document_tokens.contributor_id IS NULL
            OR document_tokens.contributor_id = EXCLUDED.contributor_id);
    IF NOT FOUND THEN RETURN 'conflict'; END IF;

    UPDATE contributors SET
        verified = TRUE,
        verified_at = NOW(),
        verification_method = 'nfc_passport+pa+self_hosted_v1',
        identity_assurance = 'strong'
    WHERE id = p_contributor_id AND status = 'active' AND banned = FALSE;
    IF NOT FOUND THEN RETURN 'account_invalid'; END IF;

    UPDATE verification_requests SET
        status = 'approved',
        review_reason = 'automatic_self_hosted_v1',
        updated_at = NOW(),
        decided_at = NOW()
    WHERE contributor_id = p_contributor_id
      AND document_token = p_document_token
      AND status = 'pending';

    INSERT INTO verification_receipts(
        request_id, contributor_id, document_token, provider, result,
        policy_version, model_set_hash, receipt_digest, receipt_signature,
        service_timestamp, evidence_protocol
    ) VALUES (
        p_request_id, p_contributor_id, p_document_token, 'self_hosted_v1', 'passed',
        p_policy_version, p_model_set_hash, p_receipt_digest, p_receipt_signature,
        p_service_timestamp, p_evidence_protocol
    );

    RETURN 'verified';
EXCEPTION WHEN unique_violation THEN
    RETURN 'conflict';
END;
$$;

REVOKE ALL ON FUNCTION activate_self_hosted_verified_id_rotating(
    TEXT, TEXT, UUID, UUID, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER
) FROM PUBLIC;

COMMIT;
