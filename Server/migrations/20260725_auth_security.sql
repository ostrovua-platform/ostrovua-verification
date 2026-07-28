-- Distributed authentication throttling and revocable sessions.
-- Apply in staging before deploying Server/server.js.

BEGIN;

CREATE TABLE IF NOT EXISTS public.auth_rate_limits (
    bucket          text        NOT NULL,
    key_hash        char(64)    NOT NULL,
    window_started  timestamptz NOT NULL DEFAULT clock_timestamp(),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    blocked_until   timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (bucket, key_hash),
    CHECK (bucket ~ '^[a-z0-9:_-]{1,64}$'),
    CHECK (key_hash ~ '^[0-9a-f]{64}$')
);

REVOKE ALL ON public.auth_rate_limits FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.auth_rate_limit_consume(
    p_bucket text,
    p_key_hash text,
    p_limit integer,
    p_window_seconds integer,
    p_block_seconds integer
)
RETURNS TABLE(allowed boolean, retry_after_seconds integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_row public.auth_rate_limits%ROWTYPE;
BEGIN
    IF p_bucket !~ '^[a-z0-9:_-]{1,64}$'
       OR p_key_hash !~ '^[0-9a-f]{64}$'
       OR p_limit < 1 OR p_limit > 10000
       OR p_window_seconds < 1 OR p_window_seconds > 86400
       OR p_block_seconds < 1 OR p_block_seconds > 604800 THEN
        RAISE EXCEPTION 'invalid auth rate-limit input';
    END IF;

    INSERT INTO public.auth_rate_limits(bucket, key_hash)
    VALUES (p_bucket, p_key_hash)
    ON CONFLICT (bucket, key_hash) DO NOTHING;

    SELECT *
      INTO v_row
      FROM public.auth_rate_limits
     WHERE bucket = p_bucket AND key_hash = p_key_hash
     FOR UPDATE;

    IF v_row.blocked_until IS NOT NULL AND v_row.blocked_until > v_now THEN
        allowed := false;
        retry_after_seconds := GREATEST(
            1,
            CEIL(EXTRACT(EPOCH FROM (v_row.blocked_until - v_now)))::integer
        );
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_row.window_started <= v_now - make_interval(secs => p_window_seconds) THEN
        UPDATE public.auth_rate_limits
           SET window_started = v_now,
               attempts = 1,
               blocked_until = NULL,
               updated_at = v_now
         WHERE bucket = p_bucket AND key_hash = p_key_hash;
        allowed := true;
        retry_after_seconds := 0;
        RETURN NEXT;
        RETURN;
    END IF;

    IF v_row.attempts + 1 > p_limit THEN
        UPDATE public.auth_rate_limits
           SET attempts = v_row.attempts + 1,
               blocked_until = v_now + make_interval(secs => p_block_seconds),
               updated_at = v_now
         WHERE bucket = p_bucket AND key_hash = p_key_hash;
        allowed := false;
        retry_after_seconds := p_block_seconds;
        RETURN NEXT;
        RETURN;
    END IF;

    UPDATE public.auth_rate_limits
       SET attempts = v_row.attempts + 1,
           blocked_until = NULL,
           updated_at = v_now
     WHERE bucket = p_bucket AND key_hash = p_key_hash;
    allowed := true;
    retry_after_seconds := 0;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.auth_rate_limit_consume(
    text, text, integer, integer, integer
) FROM PUBLIC;

CREATE TABLE IF NOT EXISTS public.auth_sessions (
    id               uuid        PRIMARY KEY,
    contributor_id   uuid        NOT NULL REFERENCES public.contributors(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_seen_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at       timestamptz NOT NULL,
    revoked_at       timestamptz,
    ip_hash          char(64),
    user_agent_hash  char(64),
    CHECK (expires_at > created_at),
    CHECK (ip_hash IS NULL OR ip_hash ~ '^[0-9a-f]{64}$'),
    CHECK (user_agent_hash IS NULL OR user_agent_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_contributor_active
    ON public.auth_sessions(contributor_id, expires_at)
    WHERE revoked_at IS NULL;

REVOKE ALL ON public.auth_sessions FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.auth_session_create(
    p_id uuid,
    p_contributor_id uuid,
    p_expires_at timestamptz,
    p_ip_hash text,
    p_user_agent_hash text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_id IS NULL OR p_contributor_id IS NULL
       OR p_expires_at <= clock_timestamp()
       OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^[0-9a-f]{64}$')
       OR (p_user_agent_hash IS NOT NULL AND p_user_agent_hash !~ '^[0-9a-f]{64}$') THEN
        RAISE EXCEPTION 'invalid auth session input';
    END IF;

    INSERT INTO public.auth_sessions(
        id, contributor_id, expires_at, ip_hash, user_agent_hash
    ) VALUES (
        p_id, p_contributor_id, p_expires_at, p_ip_hash, p_user_agent_hash
    );
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.auth_session_is_active(
    p_id uuid,
    p_contributor_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_active boolean;
BEGIN
    SELECT true
      INTO v_active
      FROM public.auth_sessions s
      JOIN public.contributors c ON c.id = s.contributor_id
     WHERE s.id = p_id
       AND s.contributor_id = p_contributor_id
       AND s.revoked_at IS NULL
       AND s.expires_at > clock_timestamp()
       AND c.banned IS NOT TRUE;

    IF COALESCE(v_active, false) THEN
        UPDATE public.auth_sessions
           SET last_seen_at = clock_timestamp()
         WHERE id = p_id
           AND last_seen_at < clock_timestamp() - interval '5 minutes';
    END IF;
    RETURN COALESCE(v_active, false);
END;
$$;

CREATE OR REPLACE FUNCTION public.auth_session_revoke(
    p_id uuid,
    p_contributor_id uuid
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH revoked AS (
        UPDATE public.auth_sessions
           SET revoked_at = COALESCE(revoked_at, clock_timestamp())
         WHERE id = p_id
           AND contributor_id = p_contributor_id
        RETURNING 1
    )
    SELECT EXISTS(SELECT 1 FROM revoked);
$$;

CREATE OR REPLACE FUNCTION public.auth_sessions_revoke_all(
    p_contributor_id uuid
)
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH revoked AS (
        UPDATE public.auth_sessions
           SET revoked_at = COALESCE(revoked_at, clock_timestamp())
         WHERE contributor_id = p_contributor_id
           AND revoked_at IS NULL
        RETURNING 1
    )
    SELECT COUNT(*)::integer FROM revoked;
$$;

REVOKE ALL ON FUNCTION public.auth_session_create(
    uuid, uuid, timestamptz, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_session_is_active(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_session_revoke(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_sessions_revoke_all(uuid) FROM PUBLIC;

-- Remove the obsolete two-argument overload before installing the
-- compare-and-swap implementation below. Leaving both signatures in place
-- would preserve a callable path that does not verify the current hash.
DROP FUNCTION IF EXISTS public.auth_change_password(uuid, text);

CREATE OR REPLACE FUNCTION public.auth_change_password(
    p_contributor_id uuid,
    p_current_password_hash text,
    p_password_hash text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_password_hash !~ '^ovua\$bcrypt-sha512\$v1\$\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' THEN
        RAISE EXCEPTION 'invalid versioned password hash';
    END IF;

    UPDATE public.contributors
       SET password_hash = p_password_hash,
           updated_at = clock_timestamp()
     WHERE id = p_contributor_id
       AND password_hash = p_current_password_hash;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    UPDATE public.auth_sessions
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE contributor_id = p_contributor_id
       AND revoked_at IS NULL;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.secure_password_reset(
    p_contributor_id uuid,
    p_candidate_hash text,
    p_password_hash text
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_reset public.password_resets%ROWTYPE;
BEGIN
    IF p_candidate_hash !~ '^[0-9a-f]{64}$'
       OR p_password_hash !~ '^ovua\$bcrypt-sha512\$v1\$\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$' THEN
        RAISE EXCEPTION 'invalid password reset input';
    END IF;

    SELECT *
      INTO v_reset
      FROM public.password_resets
     WHERE contributor_id = p_contributor_id
       AND used = false
     ORDER BY created_at DESC
     LIMIT 1
     FOR UPDATE;

    IF v_reset.id IS NULL
       OR v_reset.expires_at <= clock_timestamp() THEN
        RETURN 'invalid_or_expired';
    END IF;
    IF v_reset.attempts >= 5 THEN
        RETURN 'attempts_exhausted';
    END IF;

    UPDATE public.password_resets
       SET attempts = attempts + 1
     WHERE id = v_reset.id;

    IF v_reset.code_hash <> p_candidate_hash THEN
        RETURN 'invalid_or_expired';
    END IF;

    UPDATE public.contributors
       SET password_hash = p_password_hash,
           updated_at = clock_timestamp()
     WHERE id = p_contributor_id;
    IF NOT FOUND THEN
        RETURN 'invalid_or_expired';
    END IF;

    UPDATE public.password_resets
       SET used = true
     WHERE contributor_id = p_contributor_id
       AND used = false;

    UPDATE public.auth_sessions
       SET revoked_at = COALESCE(revoked_at, clock_timestamp())
     WHERE contributor_id = p_contributor_id
       AND revoked_at IS NULL;

    RETURN 'changed';
END;
$$;

REVOKE ALL ON FUNCTION public.auth_change_password(uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.secure_password_reset(uuid, text, text) FROM PUBLIC;

CREATE TABLE IF NOT EXISTS public.uploaded_files (
    filename         text        PRIMARY KEY,
    contributor_id  uuid        NOT NULL REFERENCES public.contributors(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (filename ~ '^[0-9a-f]{32}\.(jpg|png|gif|webp|heic|avif|mp4|mov|m4a|webm|pdf)$')
);
CREATE INDEX IF NOT EXISTS idx_uploaded_files_contributor
    ON public.uploaded_files(contributor_id);
REVOKE ALL ON public.uploaded_files FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.uploaded_file_register(
    p_filename text,
    p_contributor_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_filename !~ '^[0-9a-f]{32}\.(jpg|png|gif|webp|heic|avif|mp4|mov|m4a|webm|pdf)$' THEN
        RAISE EXCEPTION 'invalid upload filename';
    END IF;
    INSERT INTO public.uploaded_files(filename, contributor_id)
    VALUES (p_filename, p_contributor_id);
    RETURN true;
END;
$$;

CREATE TABLE IF NOT EXISTS public.account_deletion_receipts (
    id            uuid        PRIMARY KEY,
    deleted_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at  timestamptz,
    deleted_counts jsonb      NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS public.account_deletion_files (
    receipt_id   uuid        NOT NULL REFERENCES public.account_deletion_receipts(id) ON DELETE CASCADE,
    filename     text        NOT NULL,
    removed_at   timestamptz,
    PRIMARY KEY (receipt_id, filename),
    CHECK (filename ~ '^[0-9a-f]{32}\.(jpg|png|gif|webp|heic|avif|mp4|mov|m4a|webm|pdf)$')
);

REVOKE ALL ON public.account_deletion_receipts FROM PUBLIC;
REVOKE ALL ON public.account_deletion_files FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.delete_account_complete(
    p_contributor_id uuid,
    p_receipt_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_email text;
    v_deleted integer;
    v_counts jsonb := '{}'::jsonb;
    v_files jsonb := '[]'::jsonb;
BEGIN
    SELECT email
      INTO v_email
      FROM public.contributors
     WHERE id = p_contributor_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('status', 'not_found', 'files', '[]'::jsonb);
    END IF;

    INSERT INTO public.account_deletion_receipts(id)
    VALUES (p_receipt_id);

    INSERT INTO public.account_deletion_files(receipt_id, filename)
    SELECT p_receipt_id, candidates.filename
      FROM (
        SELECT filename
          FROM public.uploaded_files
         WHERE contributor_id = p_contributor_id
        UNION
        SELECT regexp_replace(attachment_url, '^.*/files/', '')
          FROM public.chat_messages
         WHERE contributor_id = p_contributor_id
           AND attachment_url IS NOT NULL
      ) AS candidates(filename)
     WHERE candidates.filename ~ '^[0-9a-f]{32}\.(jpg|png|gif|webp|heic|avif|mp4|mov|m4a|webm|pdf)$'
    ON CONFLICT DO NOTHING;

    DELETE FROM public.invited_emails
     WHERE lower(email) = lower(v_email)
        OR invited_by = p_contributor_id::text;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    v_counts := v_counts || jsonb_build_object('invites', v_deleted);

    -- Audit JSON may contain snapshots of the profile even when no FK points
    -- at contributors. Remove every matching audit entry before the profile.
    DELETE FROM public.activity_log
     WHERE entity_id = p_contributor_id
        OR COALESCE(old_data::text, '') LIKE '%' || p_contributor_id::text || '%'
        OR COALESCE(new_data::text, '') LIKE '%' || p_contributor_id::text || '%'
        OR COALESCE(changes::text, '') LIKE '%' || p_contributor_id::text || '%'
        OR (v_email IS NOT NULL AND (
             COALESCE(old_data::text, '') ILIKE '%' || v_email || '%'
          OR COALESCE(new_data::text, '') ILIKE '%' || v_email || '%'
          OR COALESCE(changes::text, '') ILIKE '%' || v_email || '%'
        ));
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    v_counts := v_counts || jsonb_build_object('audit_rows', v_deleted);

    DELETE FROM public.contributors WHERE id = p_contributor_id;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    IF v_deleted <> 1 THEN
        RAISE EXCEPTION 'account deletion lost contributor lock';
    END IF;
    v_counts := v_counts || jsonb_build_object('contributors', v_deleted);

    SELECT COALESCE(jsonb_agg(filename ORDER BY filename), '[]'::jsonb)
      INTO v_files
      FROM public.account_deletion_files
     WHERE receipt_id = p_receipt_id;

    UPDATE public.account_deletion_receipts
       SET deleted_counts = v_counts,
           completed_at = CASE WHEN jsonb_array_length(v_files) = 0
                               THEN clock_timestamp() ELSE NULL END
     WHERE id = p_receipt_id;

    RETURN jsonb_build_object(
        'status', 'deleted',
        'receiptId', p_receipt_id,
        'files', v_files,
        'counts', v_counts
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.account_deletion_file_removed(
    p_receipt_id uuid,
    p_filename text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_updated integer;
BEGIN
    UPDATE public.account_deletion_files
       SET removed_at = COALESCE(removed_at, clock_timestamp())
     WHERE receipt_id = p_receipt_id
       AND filename = p_filename;
    GET DIAGNOSTICS v_updated = ROW_COUNT;
    IF v_updated <> 1 THEN
        RETURN false;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.account_deletion_files
         WHERE receipt_id = p_receipt_id AND removed_at IS NULL
    ) THEN
        UPDATE public.account_deletion_receipts
           SET completed_at = COALESCE(completed_at, clock_timestamp())
         WHERE id = p_receipt_id;
    END IF;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION public.account_deletion_pending_files(
    p_limit integer DEFAULT 100
)
RETURNS TABLE(receipt_id uuid, filename text)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT f.receipt_id, f.filename
      FROM public.account_deletion_files f
     WHERE f.removed_at IS NULL
     ORDER BY f.receipt_id, f.filename
     LIMIT LEAST(GREATEST(p_limit, 1), 1000);
$$;

REVOKE ALL ON FUNCTION public.uploaded_file_register(text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.delete_account_complete(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.account_deletion_file_removed(uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.account_deletion_pending_files(integer) FROM PUBLIC;

COMMIT;
