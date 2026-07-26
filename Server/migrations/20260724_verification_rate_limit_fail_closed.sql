BEGIN;

-- Non-incrementing health/lock check for critical verification boundaries.
-- document_auth and approve call this function so loss of PostgreSQL cannot
-- silently fall back to a process-local limiter. Only liveness issuance calls
-- rl_touch, therefore one human attempt is counted exactly once.
CREATE OR REPLACE FUNCTION public.rl_check(p_key text)
RETURNS TABLE(is_locked boolean, until timestamptz, cur_tier integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $function$
DECLARE
    r verify_rate_limit%ROWTYPE;
BEGIN
    IF p_key IS NULL OR
       (p_key !~ '^acct:[0-9a-fA-F-]{36}$' AND
        p_key !~ '^dev:[A-Za-z0-9+/=_-]{1,64}$') THEN
        RAISE EXCEPTION 'invalid verification rate-limit key';
    END IF;

    SELECT * INTO r
      FROM verify_rate_limit
     WHERE rl_key = p_key
     FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO verify_rate_limit(rl_key)
        VALUES (p_key)
        ON CONFLICT (rl_key) DO NOTHING;

        SELECT * INTO STRICT r
          FROM verify_rate_limit
         WHERE rl_key = p_key
         FOR UPDATE;
    END IF;

    RETURN QUERY
    SELECT
        r.locked_until IS NOT NULL AND r.locked_until > now(),
        CASE WHEN r.locked_until > now() THEN r.locked_until
             ELSE NULL::timestamptz END,
        r.tier;
END;
$function$;

REVOKE ALL ON FUNCTION public.rl_check(text) FROM PUBLIC;

COMMENT ON FUNCTION public.rl_check(text) IS
  'Fail-closed, non-incrementing persistent lock check for critical verification endpoints.';

CREATE OR REPLACE FUNCTION public.rl_reset(p_key text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $function$
BEGIN
    IF p_key IS NULL OR
       (p_key !~ '^acct:[0-9a-fA-F-]{36}$' AND
        p_key !~ '^dev:[A-Za-z0-9+/=_-]{1,64}$') THEN
        RAISE EXCEPTION 'invalid verification rate-limit key';
    END IF;

    UPDATE verify_rate_limit
       SET attempts = 0,
           tier = 0,
           locked_until = NULL,
           updated_at = now()
     WHERE rl_key = p_key;
END;
$function$;

REVOKE ALL ON FUNCTION public.rl_reset(text) FROM PUBLIC;

COMMENT ON FUNCTION public.rl_reset(text) IS
  'Reset a validated verification account/device key after a successful verified flow.';

COMMIT;
