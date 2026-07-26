#!/bin/sh
set -eu

pg_container="${PG_CONTAINER:-ostrovua-v7-staging-postgres}"
pg_user="${PGUSER:-postgres}"
pg_database="${PGDATABASE:-postgres}"
parallelism="${V7_RACE_PARALLELISM:-24}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ostrovua-v7-race.XXXXXX")"

cleanup() {
    rm -rf "$work_dir"
}
trap cleanup EXIT HUP INT TERM

psql_exec() {
    docker exec --interactive "$pg_container" psql \
        --username "$pg_user" \
        --dbname "$pg_database" \
        --no-psqlrc \
        --set ON_ERROR_STOP=1 \
        "$@"
}

psql_exec --quiet <<'SQL'
-- Keep restored production rows intact. The race corpus owns only the
-- synthetic 00000000-... contributor range and its dedicated limiter key.
DELETE FROM document_ca_receipts
 WHERE contributor_id::text LIKE '00000000-0000-4001-8000-%';
DELETE FROM verification_receipts
 WHERE contributor_id::text LIKE '00000000-0000-4001-8000-%';
DELETE FROM verification_requests
 WHERE contributor_id::text LIKE '00000000-0000-4001-8000-%';
DELETE FROM document_tokens
 WHERE contributor_id::text LIKE '00000000-0000-4001-8000-%';
DELETE FROM contributors
 WHERE id::text LIKE '00000000-0000-4001-8000-%';
DELETE FROM verify_rate_limit
 WHERE rl_key = 'dev:staging-race-device';

INSERT INTO contributors(id, name, role, description, status)
SELECT (
    '00000000-0000-4001-8000-' ||
    lpad(generate_series::text, 12, '0')
)::uuid,
    'v7-race-' || generate_series::text,
    'tester',
    'isolated staging race fixture',
    'active'
FROM generate_series(1, 64);
SQL

i=1
pids=""
while [ "$i" -le "$parallelism" ]; do
    contributor_id="$(printf '00000000-0000-4001-8000-%012d' "$i")"
    request_id="$(printf '10000000-0000-4001-8000-%012d' "$i")"
    (
        psql_exec --tuples-only --no-align --quiet \
            --command "SELECT pg_sleep(0.4); SELECT activate_self_hosted_verified_id_v7_rotating(repeat('9',64), NULL, '$contributor_id', '$request_id', 'ostrovua-self-hosted-2026-07-v1', repeat('b',64), repeat('c',64), repeat('d',64), EXTRACT(EPOCH FROM NOW())::BIGINT, 7, 'active_authentication');" \
            >"$work_dir/activation.$i" 2>"$work_dir/activation.$i.err"
    ) &
    pids="$pids $!"
    i=$((i + 1))
done
job_failure=0
for pid in $pids; do
    wait "$pid" || job_failure=1
done
if [ "$job_failure" -ne 0 ]; then
    echo "activation race: at least one database call failed" >&2
    sed -n '1,120p' "$work_dir"/activation.*.err >&2
    exit 1
fi

verified_results="$(grep -hx 'verified' "$work_dir"/activation.* | wc -l | tr -d ' ')"
duplicate_results="$(grep -hx 'duplicate' "$work_dir"/activation.* | wc -l | tr -d ' ')"
if [ "$verified_results" -ne 1 ]; then
    echo "activation race: expected exactly one verified result, got $verified_results" >&2
    sed -n '1,120p' "$work_dir"/activation.[0-9]* >&2
    exit 1
fi
if [ "$duplicate_results" -ne $((parallelism - 1)) ]; then
    echo "activation race: expected $((parallelism - 1)) duplicate results, got $duplicate_results" >&2
    sed -n '1,120p' "$work_dir"/activation.[0-9]* >&2
    exit 1
fi

psql_exec --quiet <<'SQL'
DO $$
BEGIN
    IF (SELECT count(*) FROM verification_receipts
         WHERE contributor_id::text LIKE '00000000-0000-4001-8000-%') <> 1 THEN
        RAISE EXCEPTION 'activation race created more than one receipt';
    END IF;
    IF (SELECT count(*) FROM contributors
         WHERE id::text LIKE '00000000-0000-4001-8000-%'
           AND verified) <> 1 THEN
        RAISE EXCEPTION 'activation race verified more than one contributor';
    END IF;
    IF (SELECT count(*) FROM document_tokens
         WHERE contributor_id::text LIKE '00000000-0000-4001-8000-%') <> 1 THEN
        RAISE EXCEPTION 'activation race assigned one document more than once';
    END IF;
END;
$$;
SQL

i=1
pids=""
while [ "$i" -le "$parallelism" ]; do
    (
        psql_exec --tuples-only --no-align --quiet \
            --command "SELECT is_locked FROM rl_check('dev:staging-race-device');" \
            >"$work_dir/check.$i" 2>"$work_dir/check.$i.err"
    ) &
    pids="$pids $!"
    i=$((i + 1))
done
job_failure=0
for pid in $pids; do
    wait "$pid" || job_failure=1
done
if [ "$job_failure" -ne 0 ]; then
    echo "rate-limit check race: at least one database call failed" >&2
    sed -n '1,120p' "$work_dir"/check.*.err >&2
    exit 1
fi

if grep -hvx 'f' "$work_dir"/check.* | grep -q .; then
    echo "rate-limit check unexpectedly locked a fresh key" >&2
    exit 1
fi

rate_rows="$(psql_exec --tuples-only --no-align --quiet \
    --command "SELECT count(*) FROM verify_rate_limit WHERE rl_key='dev:staging-race-device' AND attempts=0 AND tier=0;")"
if [ "$rate_rows" -ne 1 ]; then
    echo "rate-limit race did not converge on one clean row" >&2
    exit 1
fi

i=1
pids=""
while [ "$i" -le 10 ]; do
    (
        psql_exec --tuples-only --no-align --quiet \
            --command "SELECT is_locked FROM rl_touch('dev:staging-race-device');" \
            >"$work_dir/touch.$i" 2>"$work_dir/touch.$i.err"
    ) &
    pids="$pids $!"
    i=$((i + 1))
done
job_failure=0
for pid in $pids; do
    wait "$pid" || job_failure=1
done
if [ "$job_failure" -ne 0 ]; then
    echo "rate-limit touch race: at least one database call failed" >&2
    sed -n '1,120p' "$work_dir"/touch.*.err >&2
    exit 1
fi

locked_results="$(grep -hx 't' "$work_dir"/touch.* | wc -l | tr -d ' ')"
if [ "$locked_results" -ne 1 ]; then
    echo "rate-limit race: expected exactly one locking request, got $locked_results" >&2
    exit 1
fi

psql_exec --quiet <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM verify_rate_limit
         WHERE rl_key = 'dev:staging-race-device'
           AND tier = 1
           AND attempts = 0
           AND locked_until > NOW()
    ) THEN
        RAISE EXCEPTION 'rate limiter did not enter the first lock tier';
    END IF;

    BEGIN
        PERFORM * FROM rl_touch('unexpected-prefix:value');
        RAISE EXCEPTION 'invalid key passed fail-closed validation';
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLERRM = 'invalid key passed fail-closed validation' THEN
                RAISE;
            END IF;
    END;
END;
$$;
SQL

# A single server-owned CA receipt may authorize one transaction only. Every
# concurrent replay uses the same contributor/document/challenge binding.
psql_exec --quiet <<'SQL'
-- The CA replay fixture owns one exact contributor. Do not erase unrelated
-- restored or activation-race evidence from the staging snapshot.
DELETE FROM document_ca_receipts
 WHERE contributor_id = '20000000-0000-4001-8000-000000000001'::uuid;
DELETE FROM verification_receipts
 WHERE contributor_id = '20000000-0000-4001-8000-000000000001'::uuid;
DELETE FROM verification_requests
 WHERE contributor_id = '20000000-0000-4001-8000-000000000001'::uuid;
DELETE FROM document_tokens
 WHERE contributor_id = '20000000-0000-4001-8000-000000000001'::uuid;
DELETE FROM contributors
 WHERE id = '20000000-0000-4001-8000-000000000001'::uuid;

INSERT INTO contributors(id, name, role, description, status)
VALUES (
    '20000000-0000-4001-8000-000000000001'::uuid,
    'v7-ca-replay',
    'tester',
    'isolated staging CA replay fixture',
    'active'
);

SELECT document_ca_record_receipt(
    '30000000-0000-4001-8000-000000000001'::uuid,
    '20000000-0000-4001-8000-000000000001'::uuid,
    repeat('A', 43) || '=',
    repeat('B', 22),
    repeat('a', 64),
    '0.4.0.127.0.7.2.2.3.2.2',
    1,
    clock_timestamp() + interval '4 minutes'
);
SQL

i=1
pids=""
while [ "$i" -le "$parallelism" ]; do
    request_suffix="$(printf '%012d' "$i")"
    request_id="40000000-0000-4001-8000-$request_suffix"
    (
        psql_exec --tuples-only --no-align --quiet \
            --command "SELECT activate_self_hosted_verified_id_v7_ca_rotating(repeat('8',64), NULL, '20000000-0000-4001-8000-000000000001', '$request_id', 'ostrovua-self-hosted-2026-07-v1', repeat('b',64), repeat('c',64), repeat('d',64), EXTRACT(EPOCH FROM NOW())::BIGINT, 7, 'chip_authentication_server', repeat('A',43) || '=', repeat('B',22), repeat('a',64));" \
            >"$work_dir/ca.$i" 2>"$work_dir/ca.$i.err"
    ) &
    pids="$pids $!"
    i=$((i + 1))
done
job_failure=0
for pid in $pids; do
    wait "$pid" || job_failure=1
done
if [ "$job_failure" -ne 0 ]; then
    echo "CA receipt race: at least one database call failed" >&2
    sed -n '1,120p' "$work_dir"/ca.*.err >&2
    exit 1
fi

ca_verified_results="$(grep -hx 'verified' "$work_dir"/ca.* | wc -l | tr -d ' ')"
ca_already_results="$(grep -hx 'already_verified' "$work_dir"/ca.* | wc -l | tr -d ' ')"
if [ "$ca_verified_results" -ne 1 ] ||
   [ "$ca_already_results" -ne $((parallelism - 1)) ]; then
    echo "CA receipt race: expected 1 verified and $((parallelism - 1)) already_verified" >&2
    sed -n '1,120p' "$work_dir"/ca.[0-9]* >&2
    exit 1
fi

psql_exec --quiet <<'SQL'
DO $$
BEGIN
    IF (SELECT count(*) FROM document_ca_receipts
         WHERE contributor_id = '20000000-0000-4001-8000-000000000001'::uuid
           AND consumed_at IS NOT NULL) <> 1 THEN
        RAISE EXCEPTION 'CA receipt was not consumed exactly once';
    END IF;
    IF (SELECT count(*) FROM verification_receipts
         WHERE contributor_id = '20000000-0000-4001-8000-000000000001'::uuid
           AND document_assurance = 'chip_authentication_server') <> 1 THEN
        RAISE EXCEPTION 'CA race created an invalid number of verification receipts';
    END IF;
END;
$$;
SQL

echo "staging_v7_race_load: PASS (activation=$parallelism, CA=$parallelism, limiter=10)"
