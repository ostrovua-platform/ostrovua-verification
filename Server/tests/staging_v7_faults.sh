#!/bin/sh
set -eu

server_dir="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
compose_file="${COMPOSE_FILE:-$server_dir/docker-compose.selfhosted.yml}"
compose_config="$(mktemp "${TMPDIR:-/tmp}/ostrovua-compose-security.XXXXXX")"

cleanup() {
    rm -f "$compose_config"
}
trap cleanup EXIT HUP INT TERM

if [ ! -r "$compose_file" ]; then
    echo "reviewed compose file is required; set COMPOSE_FILE explicitly: $compose_file" >&2
    exit 1
fi

require_literal_zero() {
    key="$1"
    if ! grep -Eq "^[[:space:]]*$key:[[:space:]]*['\"]0['\"]([[:space:]]*(#.*)?)$" "$compose_file"; then
        echo "$key is not pinned to literal 0 in $compose_file" >&2
        exit 1
    fi
}

require_literal_zero SELF_HOSTED_VERIFICATION_ENABLED
require_literal_zero BIOMETRIC_CALIBRATION_APPROVED
require_literal_zero BIOMETRIC_SHADOW_MODE_ENABLED
require_literal_zero SERVER_OWNED_CA_ENABLED

if grep -Eq '^[[:space:]]*BIOMETRIC_HMAC_SECRET:' "$compose_file"; then
    echo "inline BIOMETRIC_HMAC_SECRET is forbidden" >&2
    exit 1
fi

if ! grep -Eq 'BIOMETRIC_HMAC_SECRET_FILE:.*biometric_hmac\.key' "$compose_file"; then
    echo "biometric HMAC file binding is missing" >&2
    exit 1
fi

if ! grep -Eq 'BIOMETRIC_ENVELOPE_PRIVATE_KEY_FILE:.*biometric_envelope_private\.key' "$compose_file"; then
    echo "biometric private-key file binding is missing" >&2
    exit 1
fi

if ! grep -Eq 'BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE:.*biometric_envelope_public\.key' "$compose_file"; then
    echo "auth public-key file binding is missing" >&2
    exit 1
fi

if grep -Eq '^[[:space:]]*DOCUMENT_CA_SEALING_KEY:' "$compose_file"; then
    echo "inline DOCUMENT_CA_SEALING_KEY is forbidden" >&2
    exit 1
fi

if ! grep -Eq 'DOCUMENT_CA_SEALING_KEY_FILE:.*document_ca_sealing\.key' "$compose_file"; then
    echo "document CA sealing-key file binding is missing" >&2
    exit 1
fi

if grep -E '^[[:space:]]*image:' "$compose_file" |
   grep -Ev '@sha256:[0-9a-f]{64}([[:space:]]*(#.*)?)$' |
   grep -q .; then
    echo "every production image must be pinned by sha256 digest" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1 ||
   ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 is required for the canonical security gate" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required for the dependency-free compose security gate" >&2
    exit 1
fi

docker compose --file "$compose_file" config --format json >"$compose_config"
python3 "$server_dir/tools/check_selfhosted_compose.py" "$compose_config"

echo "staging_v7_faults: PASS"
