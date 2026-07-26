BEGIN;

ALTER TABLE public.contributors
    ADD COLUMN IF NOT EXISTS oauth_provider text,
    ADD COLUMN IF NOT EXISTS oauth_provider_id text,
    ADD COLUMN IF NOT EXISTS oauth_email_verified_at timestamptz;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM public.contributors
         WHERE email IS NOT NULL
         GROUP BY lower(btrim(email))
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot normalize contributor email: case-insensitive duplicates exist';
    END IF;
END
$$;

UPDATE public.contributors
   SET email = lower(btrim(email))
 WHERE email IS NOT NULL
   AND email IS DISTINCT FROM lower(btrim(email));

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.contributors'::regclass
           AND conname = 'contributors_oauth_identity_pair_ck'
    ) THEN
        ALTER TABLE public.contributors
            ADD CONSTRAINT contributors_oauth_identity_pair_ck CHECK (
                (oauth_provider IS NULL) = (oauth_provider_id IS NULL)
                AND (
                    oauth_provider IS NULL
                    OR (
                        oauth_provider ~ '^[a-z][a-z0-9_-]{0,31}$'
                        AND length(oauth_provider_id) BETWEEN 1 AND 255
                    )
                )
            );
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS contributors_oauth_identity_uidx
    ON public.contributors(oauth_provider, oauth_provider_id)
    WHERE oauth_provider IS NOT NULL AND oauth_provider_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS contributors_normalized_email_uidx
    ON public.contributors(lower(email))
    WHERE email IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.contributors'::regclass
           AND conname = 'contributors_email_normalized_ck'
    ) THEN
        ALTER TABLE public.contributors
            ADD CONSTRAINT contributors_email_normalized_ck CHECK (
                email IS NULL OR (
                    email = lower(btrim(email))
                    AND length(email) BETWEEN 3 AND 254
                )
            );
    END IF;
END
$$;

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
    IF NOT EXISTS (
        SELECT 1
          FROM public.contributors c
         WHERE c.id = p_contributor_id
           AND c.status = 'active'
           AND c.banned IS NOT TRUE
    ) THEN
        RAISE EXCEPTION 'contributor is not active';
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
       AND c.status = 'active'
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

REVOKE ALL ON FUNCTION public.auth_session_create(
    uuid, uuid, timestamptz, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_session_is_active(uuid, uuid) FROM PUBLIC;

COMMIT;
