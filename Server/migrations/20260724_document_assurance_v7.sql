BEGIN;

-- Protocol v7 records the anti-cloning assurance that justified the outcome.
-- Historical v5/v6 rows remain readable, but only the v7 entry points below
-- can create new production decisions.
ALTER TABLE verification_requests
    ADD COLUMN IF NOT EXISTS document_assurance TEXT;
ALTER TABLE verification_requests
    DROP CONSTRAINT IF EXISTS verification_requests_document_assurance_check;
ALTER TABLE verification_requests
    ADD CONSTRAINT verification_requests_document_assurance_check
    CHECK (
        document_assurance IS NULL OR
        document_assurance IN (
            'passive_only', 'chip_authentication_attested',
            'active_authentication'
        )
    );
ALTER TABLE verification_requests
    DROP CONSTRAINT IF EXISTS verification_requests_v7_assurance_check;
ALTER TABLE verification_requests
    ADD CONSTRAINT verification_requests_v7_assurance_check
    CHECK (evidence_protocol < 7 OR document_assurance IS NOT NULL);

ALTER TABLE verification_receipts
    ADD COLUMN IF NOT EXISTS document_assurance TEXT;
ALTER TABLE verification_receipts
    DROP CONSTRAINT IF EXISTS verification_receipts_evidence_protocol_check;
ALTER TABLE verification_receipts
    ADD CONSTRAINT verification_receipts_evidence_protocol_check
    CHECK (evidence_protocol IN (6, 7));
ALTER TABLE verification_receipts
    DROP CONSTRAINT IF EXISTS verification_receipts_document_assurance_check;
ALTER TABLE verification_receipts
    ADD CONSTRAINT verification_receipts_document_assurance_check
    CHECK (
        (evidence_protocol = 6 AND document_assurance IS NULL) OR
        (evidence_protocol = 7 AND
         document_assurance = 'active_authentication')
    );

-- The v5 review function is retained only as an internal transactional
-- primitive. This wrapper accepts protocol 7 exclusively and upgrades the row
-- before commit. If the assurance update cannot be made, the complete call is
-- rolled back.
CREATE OR REPLACE FUNCTION submit_verification_review_v7_rotating(
    p_document_token         TEXT,
    p_legacy_document_token  TEXT,
    p_contributor_id         UUID,
    p_face_model             TEXT,
    p_face_model_version     TEXT,
    p_face_score             NUMERIC,
    p_face_threshold         NUMERIC,
    p_face_sample_count      INTEGER,
    p_face_continuity_score  NUMERIC,
    p_liveness_frame_count   INTEGER,
    p_liveness_duration_ms   INTEGER,
    p_evidence_protocol      INTEGER,
    p_document_assurance     TEXT
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_result TEXT;
    v_updated INTEGER;
BEGIN
    IF p_evidence_protocol IS DISTINCT FROM 7 OR
       p_document_assurance IS NULL OR
       p_document_assurance NOT IN (
           'passive_only', 'chip_authentication_attested'
       ) THEN
        RETURN 'invalid';
    END IF;

    SELECT submit_verification_review_rotating(
        p_document_token,
        p_legacy_document_token,
        p_contributor_id,
        p_face_model,
        p_face_model_version,
        p_face_score,
        p_face_threshold,
        p_face_sample_count,
        p_face_continuity_score,
        p_liveness_frame_count,
        p_liveness_duration_ms,
        5
    ) INTO v_result;

    IF v_result = 'pending' THEN
        UPDATE verification_requests
           SET evidence_protocol = 7,
               document_assurance = p_document_assurance,
               review_reason = CASE p_document_assurance
                   WHEN 'chip_authentication_attested'
                       THEN 'ca_attested_server_transcript_required'
                   ELSE 'passive_document_no_aa_or_ca'
               END,
               updated_at = NOW()
         WHERE contributor_id = p_contributor_id
           AND document_token = ANY(
               ARRAY[p_document_token, p_legacy_document_token]
           )
           AND status = 'pending';
        GET DIAGNOSTICS v_updated = ROW_COUNT;
        IF v_updated <> 1 THEN
            RAISE EXCEPTION 'v7 review assurance update invariant failed';
        END IF;
    END IF;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION submit_verification_review_v7_rotating(
    TEXT, TEXT, UUID, TEXT, TEXT, NUMERIC, NUMERIC, INTEGER, NUMERIC,
    INTEGER, INTEGER, INTEGER, TEXT
) FROM PUBLIC;

-- The v6 activation function remains the already-reviewed transactional claim
-- primitive. This v7 wrapper permits activation only after AA or CA and
-- atomically upgrades the receipt and contributor method before commit.
CREATE OR REPLACE FUNCTION activate_self_hosted_verified_id_v7_rotating(
    p_document_token         TEXT,
    p_legacy_document_token  TEXT,
    p_contributor_id         UUID,
    p_request_id             UUID,
    p_policy_version         TEXT,
    p_model_set_hash         TEXT,
    p_receipt_digest         TEXT,
    p_receipt_signature      TEXT,
    p_service_timestamp      BIGINT,
    p_evidence_protocol      INTEGER,
    p_document_assurance     TEXT
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_result TEXT;
    v_updated INTEGER;
BEGIN
    IF p_evidence_protocol IS DISTINCT FROM 7 OR
       p_document_assurance IS NULL OR
       p_document_assurance IS DISTINCT FROM
           'active_authentication' THEN
        RETURN 'invalid';
    END IF;

    SELECT activate_self_hosted_verified_id_rotating(
        p_document_token,
        p_legacy_document_token,
        p_contributor_id,
        p_request_id,
        p_policy_version,
        p_model_set_hash,
        p_receipt_digest,
        p_receipt_signature,
        p_service_timestamp,
        6
    ) INTO v_result;

    IF v_result = 'verified' THEN
        UPDATE verification_receipts
           SET evidence_protocol = 7,
               document_assurance = p_document_assurance
         WHERE request_id = p_request_id
           AND contributor_id = p_contributor_id;
        GET DIAGNOSTICS v_updated = ROW_COUNT;
        IF v_updated <> 1 THEN
            RAISE EXCEPTION 'v7 receipt assurance update invariant failed';
        END IF;

        UPDATE contributors
           SET verification_method = 'nfc_passport+pa+aa+self_hosted_v1',
               identity_assurance = 'strong'
         WHERE id = p_contributor_id
           AND verified = TRUE;
        GET DIAGNOSTICS v_updated = ROW_COUNT;
        IF v_updated <> 1 THEN
            RAISE EXCEPTION 'v7 contributor assurance update invariant failed';
        END IF;
    END IF;

    RETURN v_result;
END;
$$;

REVOKE ALL ON FUNCTION activate_self_hosted_verified_id_v7_rotating(
    TEXT, TEXT, UUID, UUID, TEXT, TEXT, TEXT, TEXT, BIGINT, INTEGER, TEXT
) FROM PUBLIC;

COMMIT;
