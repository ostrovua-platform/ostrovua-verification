BEGIN;

-- Черга заявок не зберігає фото, ембеддінги, MRZ або номер документа.
-- document_token = HMAC(server pepper, підписаний державою DG1 hash).
CREATE TABLE IF NOT EXISTS verification_requests (
    id                     BIGSERIAL PRIMARY KEY,
    contributor_id         UUID NOT NULL REFERENCES contributors(id) ON DELETE CASCADE,
    document_token         TEXT NOT NULL CHECK (document_token ~ '^[0-9a-f]{64}$'),
    status                 TEXT NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','approved','rejected','cancelled')),
    passive_authentication TEXT NOT NULL CHECK (passive_authentication = 'passed'),
    liveness_method        TEXT NOT NULL CHECK (liveness_method = 'active'),
    face_model             TEXT NOT NULL,
    face_model_version     TEXT NOT NULL,
    face_score             NUMERIC(7,6) NOT NULL CHECK (face_score BETWEEN -1 AND 1),
    face_threshold         NUMERIC(7,6) NOT NULL CHECK (face_threshold BETWEEN -1 AND 1),
    face_sample_count      SMALLINT NOT NULL CHECK (face_sample_count BETWEEN 3 AND 5),
    face_continuity_score  NUMERIC(7,6) NOT NULL CHECK (face_continuity_score BETWEEN -1 AND 1),
    liveness_frame_count   INTEGER NOT NULL CHECK (liveness_frame_count BETWEEN 8 AND 3000),
    liveness_duration_ms   INTEGER NOT NULL CHECK (liveness_duration_ms BETWEEN 500 AND 30000),
    evidence_protocol      SMALLINT NOT NULL CHECK (evidence_protocol >= 5),
    review_reason          TEXT NOT NULL DEFAULT 'server_biometric_review_required',
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at             TIMESTAMPTZ
);

-- Один документ і один акаунт можуть мати лише одну активну заявку.
CREATE UNIQUE INDEX IF NOT EXISTS uq_verification_request_active_document
    ON verification_requests(document_token)
    WHERE status IN ('pending','approved');
CREATE UNIQUE INDEX IF NOT EXISTS uq_verification_request_active_contributor
    ON verification_requests(contributor_id)
    WHERE status IN ('pending','approved');
CREATE INDEX IF NOT EXISTS idx_verification_requests_status_created
    ON verification_requests(status, created_at);

CREATE OR REPLACE FUNCTION submit_verification_review(
    p_document_token        TEXT,
    p_contributor_id        UUID,
    p_face_model            TEXT,
    p_face_model_version    TEXT,
    p_face_score            NUMERIC,
    p_face_threshold        NUMERIC,
    p_face_sample_count     INTEGER,
    p_face_continuity_score NUMERIC,
    p_liveness_frame_count  INTEGER,
    p_liveness_duration_ms  INTEGER,
    p_evidence_protocol     INTEGER
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_doc_owner UUID;
    v_doc_status TEXT;
    v_request_id BIGINT;
    v_request_owner UUID;
    v_other_document TEXT;
BEGIN
    IF p_document_token !~ '^[0-9a-f]{64}$'
       OR p_face_model <> 'coreml'
       OR p_face_model_version <> 'facenet-vggface2-coreml-04a4db780288799e'
       OR p_face_score < p_face_threshold
       OR p_face_threshold <> 0.5
       OR p_face_sample_count NOT BETWEEN 3 AND 5
       OR p_face_continuity_score < 0.4
       OR p_liveness_frame_count NOT BETWEEN 8 AND 3000
       OR p_liveness_duration_ms NOT BETWEEN 500 AND 30000
       OR p_evidence_protocol <> 5 THEN
        RETURN 'invalid';
    END IF;

    -- Однаковий порядок advisory locks для всіх викликів прибирає гонки
    -- між двома документами одного акаунта та одним документом двох акаунтів.
    PERFORM pg_advisory_xact_lock(hashtextextended('contributor:' || p_contributor_id::text, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended('document:' || p_document_token, 0));

    SELECT contributor_id, status INTO v_doc_owner, v_doc_status
      FROM document_tokens WHERE token = p_document_token FOR UPDATE;
    IF FOUND THEN
        IF v_doc_status = 'banned' THEN RETURN 'banned'; END IF;
        IF v_doc_owner IS DISTINCT FROM p_contributor_id THEN RETURN 'duplicate'; END IF;
        IF v_doc_owner = p_contributor_id THEN RETURN 'already_verified'; END IF;
    END IF;

    SELECT id, contributor_id INTO v_request_id, v_request_owner
      FROM verification_requests
     WHERE document_token = p_document_token AND status IN ('pending','approved')
     ORDER BY id DESC LIMIT 1 FOR UPDATE;
    IF FOUND AND v_request_owner IS DISTINCT FROM p_contributor_id THEN
        RETURN 'duplicate';
    END IF;

    SELECT document_token INTO v_other_document
      FROM verification_requests
     WHERE contributor_id = p_contributor_id AND status IN ('pending','approved')
     ORDER BY id DESC LIMIT 1 FOR UPDATE;
    IF FOUND AND v_other_document <> p_document_token THEN
        RETURN 'contributor_conflict';
    END IF;

    IF v_request_id IS NOT NULL THEN
        UPDATE verification_requests SET
            face_score = p_face_score,
            face_threshold = p_face_threshold,
            face_sample_count = p_face_sample_count,
            face_continuity_score = p_face_continuity_score,
            liveness_frame_count = p_liveness_frame_count,
            liveness_duration_ms = p_liveness_duration_ms,
            evidence_protocol = p_evidence_protocol,
            updated_at = NOW()
        WHERE id = v_request_id;
        RETURN 'pending';
    END IF;

    INSERT INTO verification_requests (
        contributor_id, document_token, status, passive_authentication,
        liveness_method, face_model, face_model_version, face_score,
        face_threshold, face_sample_count, face_continuity_score,
        liveness_frame_count, liveness_duration_ms, evidence_protocol
    ) VALUES (
        p_contributor_id, p_document_token, 'pending', 'passed',
        'active', p_face_model, p_face_model_version, p_face_score,
        p_face_threshold, p_face_sample_count, p_face_continuity_score,
        p_liveness_frame_count, p_liveness_duration_ms, p_evidence_protocol
    );
    RETURN 'pending';
EXCEPTION WHEN unique_violation THEN
    RETURN 'conflict';
END;
$$;

REVOKE ALL ON FUNCTION submit_verification_review(
    TEXT, UUID, TEXT, TEXT, NUMERIC, NUMERIC, INTEGER, NUMERIC, INTEGER, INTEGER, INTEGER
) FROM PUBLIC;

COMMIT;
