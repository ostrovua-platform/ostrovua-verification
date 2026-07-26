-- Give a first-time identity-verification session enough room for real-world
-- NFC / face-capture retries, while making later tiers progressively stricter.
-- Tier 0: 10 attempts -> 1 hour; tier 1: 7 -> 1 day;
-- tier 2: 5 -> 7 days; another exhausted tier becomes an appeal-only lock.

BEGIN;

CREATE OR REPLACE FUNCTION public.rl_touch(p_key text)
RETURNS TABLE(is_locked boolean, until timestamptz, cur_tier integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $function$
DECLARE
    r   verify_rate_limit%ROWTYPE;
    thr int[]      := ARRAY[10, 7, 5];
    dur interval[] := ARRAY['1 hour', '1 day', '7 days']::interval[];
    idx int;
    need int;
BEGIN
    IF p_key IS NULL OR
       (p_key !~ '^acct:[0-9a-fA-F-]{36}$' AND
        p_key !~ '^dev:[A-Za-z0-9+/=_-]{1,64}$') THEN
        RAISE EXCEPTION 'invalid verification rate-limit key';
    END IF;

    SELECT * INTO r FROM verify_rate_limit WHERE rl_key = p_key FOR UPDATE;
    IF NOT FOUND THEN
        INSERT INTO verify_rate_limit(rl_key) VALUES (p_key)
            ON CONFLICT (rl_key) DO NOTHING;
        SELECT * INTO r FROM verify_rate_limit WHERE rl_key = p_key FOR UPDATE;
    END IF;

    IF r.locked_until IS NOT NULL AND r.locked_until > now() THEN
        RETURN QUERY SELECT true, r.locked_until, r.tier;
        RETURN;
    END IF;

    r.attempts := r.attempts + 1;
    idx  := LEAST(r.tier, 2) + 1;
    need := thr[idx];

    IF r.attempts < need THEN
        UPDATE verify_rate_limit
           SET attempts = r.attempts, updated_at = now()
         WHERE rl_key = p_key;
        RETURN QUERY SELECT false, NULL::timestamptz, r.tier;
        RETURN;
    END IF;

    IF r.tier >= 3 THEN
        UPDATE verify_rate_limit
           SET attempts = 0,
               tier = r.tier + 1,
               locked_until = now() + interval '100 years',
               updated_at = now()
         WHERE rl_key = p_key;
        RETURN QUERY SELECT true, now() + interval '100 years', r.tier + 1;
    ELSE
        UPDATE verify_rate_limit
           SET attempts = 0,
               tier = r.tier + 1,
               locked_until = now() + dur[idx],
               updated_at = now()
         WHERE rl_key = p_key;
        RETURN QUERY SELECT true, now() + dur[idx], r.tier + 1;
    END IF;
END;
$function$;

REVOKE ALL ON FUNCTION public.rl_touch(text) FROM PUBLIC;

COMMENT ON FUNCTION public.rl_touch(text) IS
  'Atomic verification-attempt limiter: first tier 10 attempts, then 7 and 5 with escalating cooldowns.';

COMMIT;
