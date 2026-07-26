BEGIN;

-- Безперервна ротація DOC_TOKEN_PEPPER без збереження MRZ/DG1 у відкритому
-- вигляді. Нові документи отримують токен від активного pepper. Для вже
-- відомих документів сервер також передає токен від попереднього pepper.
-- Обидва ідентифікатори перевіряються в ОДНІЙ транзакції та під однаково
-- впорядкованими advisory-lock, тому duplicate/ban інваріанти не слабшають.
CREATE OR REPLACE FUNCTION submit_verification_review_rotating(
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
    p_evidence_protocol      INTEGER
) RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_candidate_token TEXT;
    v_effective_token TEXT := p_document_token;
    v_doc_owner UUID;
    v_doc_status TEXT;
    v_request_id BIGINT;
    v_request_owner UUID;
    v_request_document_token TEXT;
    v_other_document TEXT;
BEGIN
    IF p_document_token !~ '^[0-9a-f]{64}$'
       OR (p_legacy_document_token IS NOT NULL
           AND (p_legacy_document_token !~ '^[0-9a-f]{64}$'
                OR p_legacy_document_token = p_document_token))
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

    PERFORM pg_advisory_xact_lock(
        hashtextextended('contributor:' || p_contributor_id::text, 0)
    );
    FOR v_candidate_token IN
        SELECT DISTINCT token
          FROM unnest(ARRAY[p_document_token, p_legacy_document_token]) AS t(token)
         WHERE token IS NOT NULL
         ORDER BY token
    LOOP
        PERFORM pg_advisory_xact_lock(
            hashtextextended('document:' || v_candidate_token, 0)
        );
    END LOOP;

    -- Спершу перевіряємо постійні claims для обох поколінь токена.
    FOR v_candidate_token, v_doc_owner, v_doc_status IN
        SELECT token, contributor_id, status
          FROM document_tokens
         WHERE token = ANY(ARRAY[p_document_token, p_legacy_document_token])
         ORDER BY token
         FOR UPDATE
    LOOP
        IF v_doc_status = 'banned' THEN RETURN 'banned'; END IF;
        IF v_doc_owner IS DISTINCT FROM p_contributor_id
           AND v_doc_owner IS NOT NULL THEN RETURN 'duplicate'; END IF;
        IF v_doc_owner = p_contributor_id THEN RETURN 'already_verified'; END IF;
        -- Неприв'язаний старий claim лишається канонічним: не створюємо
        -- другий запис того самого документа під новим pepper.
        v_effective_token := v_candidate_token;
    END LOOP;

    -- Те саме для активної review-черги. Якщо заявка вже існує під старим
    -- токеном, оновлюємо саме її, а не створюємо паралельну.
    SELECT id, contributor_id, document_token
      INTO v_request_id, v_request_owner, v_request_document_token
      FROM verification_requests
     WHERE document_token = ANY(ARRAY[p_document_token, p_legacy_document_token])
       AND status IN ('pending','approved')
     ORDER BY id DESC LIMIT 1 FOR UPDATE;
    IF FOUND AND v_request_owner IS DISTINCT FROM p_contributor_id THEN
        RETURN 'duplicate';
    END IF;
    IF v_request_id IS NOT NULL THEN
        v_effective_token := v_request_document_token;
    END IF;

    SELECT document_token INTO v_other_document
      FROM verification_requests
     WHERE contributor_id = p_contributor_id AND status IN ('pending','approved')
     ORDER BY id DESC LIMIT 1 FOR UPDATE;
    IF FOUND
       AND v_other_document <> p_document_token
       AND (p_legacy_document_token IS NULL
            OR v_other_document <> p_legacy_document_token) THEN
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
        p_contributor_id, v_effective_token, 'pending', 'passed',
        'active', p_face_model, p_face_model_version, p_face_score,
        p_face_threshold, p_face_sample_count, p_face_continuity_score,
        p_liveness_frame_count, p_liveness_duration_ms, p_evidence_protocol
    );
    RETURN 'pending';
EXCEPTION WHEN unique_violation THEN
    RETURN 'conflict';
END;
$$;

REVOKE ALL ON FUNCTION submit_verification_review_rotating(
    TEXT, TEXT, UUID, TEXT, TEXT, NUMERIC, NUMERIC, INTEGER, NUMERIC,
    INTEGER, INTEGER, INTEGER
) FROM PUBLIC;

COMMIT;
