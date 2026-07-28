#!/usr/bin/env python3
"""Fail-closed gate for the canonical self-hosted production compose config."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


DIGEST_IMAGE = re.compile(r"^[^\s@]+(?:/[^\s@]+)*@sha256:[0-9a-f]{64}$")
INLINE_SECRETS = {
    "BIOMETRIC_HMAC_SECRET",
    "BIOMETRIC_ENVELOPE_PRIVATE_KEY",
    "BIOMETRIC_ENVELOPE_PUBLIC_KEY",
    "DOCUMENT_CA_SEALING_KEY",
}


def fail(message: str) -> None:
    raise SystemExit(f"compose security gate: {message}")


def environment(service: dict) -> dict[str, str]:
    value = service.get("environment", {})
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    fail("canonical service environment is not an object")


def require_service(services: dict, name: str) -> dict:
    service = services.get(name)
    if not isinstance(service, dict):
        fail(f"service {name!r} is missing; available={sorted(services)}")
    return service


def require_flag(env: dict[str, str], name: str) -> None:
    if env.get(name) != "0":
        fail(f"{name} must resolve to literal 0")


def require_secret_file(env: dict[str, str], name: str, basename: str) -> None:
    value = env.get(name, "")
    if value != f"/run/secrets/{basename}":
        fail(f"{name} must resolve to /run/secrets/{basename}")


def require_secret_mount(service: dict, basename: str) -> None:
    mounts = service.get("secrets", [])
    targets = {
        Path(str(item.get("target", ""))).name
        for item in mounts
        if isinstance(item, dict)
    }
    if basename not in targets:
        fail(f"service is missing Docker secret target {basename!r}")


def service_network_names(service: dict) -> set[str]:
    value = service.get("networks", {})
    if isinstance(value, dict):
        return set(value)
    if isinstance(value, list):
        return {str(item) for item in value}
    fail("canonical service networks have an invalid shape")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check_selfhosted_compose.py COMPOSE_CONFIG_JSON")
    try:
        config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"cannot read canonical compose JSON: {error}")

    services = config.get("services")
    networks = config.get("networks")
    if not isinstance(services, dict) or not isinstance(networks, dict):
        fail("canonical compose must contain service and network objects")

    auth_name = os.environ.get("AUTH_SERVICE", "auth")
    biometric_name = os.environ.get("BIOMETRIC_SERVICE", "biometric")
    edge_name = os.environ.get("PUBLIC_EDGE_SERVICE", "nginx")
    auth = require_service(services, auth_name)
    biometric = require_service(services, biometric_name)
    require_service(services, edge_name)

    auth_env = environment(auth)
    biometric_env = environment(biometric)
    for service in services.values():
        env = environment(service)
        exposed = INLINE_SECRETS.intersection(env)
        if exposed:
            fail(f"inline secrets are forbidden: {sorted(exposed)}")

    require_flag(auth_env, "SELF_HOSTED_VERIFICATION_ENABLED")
    require_flag(auth_env, "BIOMETRIC_SHADOW_MODE_ENABLED")
    require_flag(auth_env, "SERVER_OWNED_CA_ENABLED")
    require_flag(auth_env, "BIOMETRIC_CALIBRATION_APPROVED")
    require_flag(auth_env, "AUTH_SESSION_ENFORCEMENT_ENABLED")
    require_flag(biometric_env, "BIOMETRIC_CALIBRATION_APPROVED")
    require_secret_file(auth_env, "BIOMETRIC_HMAC_SECRET_FILE", "biometric_hmac.key")
    require_secret_file(
        biometric_env, "BIOMETRIC_HMAC_SECRET_FILE", "biometric_hmac.key"
    )
    require_secret_file(
        auth_env,
        "BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE",
        "biometric_envelope_public.key",
    )
    require_secret_file(
        biometric_env,
        "BIOMETRIC_ENVELOPE_PRIVATE_KEY_FILE",
        "biometric_envelope_private.key",
    )
    require_secret_file(
        auth_env, "DOCUMENT_CA_SEALING_KEY_FILE", "document_ca_sealing.key"
    )
    require_secret_file(
        auth_env, "AUTH_RATE_LIMIT_PEPPER_FILE", "auth_rate_limit_pepper.key"
    )
    require_secret_file(
        auth_env,
        "AUTH_SESSION_METADATA_PEPPER_FILE",
        "auth_session_metadata_pepper.key",
    )
    require_secret_file(
        auth_env, "PASSWORD_RESET_PEPPER_FILE", "password_reset_pepper.key"
    )
    if auth_env.get("APP_ENV") != "production" or \
       biometric_env.get("APP_ENV") != "production":
        fail("auth and biometric services must run with APP_ENV=production")
    if auth_env.get("BIOMETRIC_SERVICE_URL") != \
       f"http://{biometric_name}:8080/v1/verify":
        fail("auth must use the internal biometric service URL")

    auth_pin = auth_env.get("BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256", "")
    worker_pin = biometric_env.get("BIOMETRIC_ENVELOPE_ACTIVE_KEY_SHA256", "")
    secondary_pin = biometric_env.get("BIOMETRIC_ENVELOPE_SECONDARY_KEY_SHA256", "")
    worker_pins = {value for value in (worker_pin, secondary_pin) if value}
    if not re.fullmatch(r"[0-9a-f]{64}", auth_pin) or \
       any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in worker_pins) or \
       auth_pin not in worker_pins:
        fail("auth envelope key pin is not in the worker trusted keyring")

    require_secret_mount(auth, "biometric_hmac.key")
    require_secret_mount(auth, "biometric_envelope_public.key")
    require_secret_mount(auth, "document_ca_sealing.key")
    require_secret_mount(auth, "auth_rate_limit_pepper.key")
    require_secret_mount(auth, "auth_session_metadata_pepper.key")
    require_secret_mount(auth, "password_reset_pepper.key")
    require_secret_mount(biometric, "biometric_hmac.key")
    require_secret_mount(biometric, "biometric_envelope_private.key")
    for mount in auth.get("volumes", []):
        if not isinstance(mount, dict):
            continue
        target = str(mount.get("target", ""))
        if target.startswith("/run/biometric-secrets") or \
           target.endswith("biometric_envelope_private.key"):
            fail("auth service must not mount the biometric private-key directory")
    secondary_path = biometric_env.get(
        "BIOMETRIC_ENVELOPE_SECONDARY_PRIVATE_KEY_FILE", "")
    if secondary_path:
        if secondary_path != "/run/secrets/biometric_envelope_secondary_private.key":
            fail("secondary biometric private key must use its Docker secret path")
        if not secondary_pin:
            fail("secondary biometric private key requires a trusted key pin")
        require_secret_mount(biometric, "biometric_envelope_secondary_private.key")
    elif secondary_pin:
        fail("secondary biometric key pin has no private-key file")

    for name, service in services.items():
        image = service.get("image")
        if not isinstance(image, str) or not DIGEST_IMAGE.fullmatch(image):
            fail(f"service {name!r} image is not pinned by sha256 digest")
        if service.get("ports") and name != edge_name:
            fail(f"only edge service {edge_name!r} may publish host ports")

    if biometric.get("read_only") is not True:
        fail("biometric root filesystem must be read-only")
    if "ALL" not in {str(value).upper() for value in biometric.get("cap_drop", [])}:
        fail("biometric service must drop ALL capabilities")
    security_options = {
        str(value).replace("=", ":").lower()
        for value in biometric.get("security_opt", [])
    }
    if "no-new-privileges:true" not in security_options:
        fail("biometric service must set no-new-privileges:true")
    try:
        pids_limit = int(biometric.get("pids_limit", 0))
        memory_limit = int(biometric.get("mem_limit", 0))
        swap_limit = int(biometric.get("memswap_limit", -1))
    except (TypeError, ValueError):
        fail("biometric runtime limits must resolve to integers")
    if not 1 <= pids_limit <= 64:
        fail("biometric pids_limit must be between 1 and 64")
    if memory_limit <= 0:
        fail("biometric mem_limit must be a resolved positive byte count")
    if swap_limit != memory_limit:
        fail("biometric memswap_limit must equal mem_limit to disable swap")
    if biometric.get("privileged") is True or biometric.get("devices"):
        fail("biometric service cannot be privileged or receive host devices")
    if str(biometric.get("user", "")).lower() in {"0", "0:0", "root", "root:root"}:
        fail("biometric service cannot override the image user with root")
    for namespace in ("network_mode", "pid", "ipc"):
        if str(biometric.get(namespace, "")).lower() == "host":
            fail(f"biometric service cannot share host {namespace}")
    ulimits = biometric.get("ulimits", {})
    core = ulimits.get("core") if isinstance(ulimits, dict) else None
    # Docker Compose canonical JSON currently normalizes an explicitly
    # configured soft=0/hard=0 pair to an empty object. The source compose is
    # checked separately before deployment and the effective HostConfig is
    # checked after container creation.
    canonical_zero = isinstance(core, dict) and not core
    explicit_zero = isinstance(core, dict) and \
        int(core.get("soft", -1)) == 0 and int(core.get("hard", -1)) == 0
    if not canonical_zero and not explicit_zero:
        fail("biometric service must set RLIMIT_CORE soft=0 and hard=0")
    for mount in biometric.get("volumes", []):
        if not isinstance(mount, dict) or mount.get("read_only") is not True:
            fail("every biometric volume mount must be long-form and read-only")

    tmpfs = biometric.get("tmpfs", [])
    tmpfs_targets = {
        str(value).split(":", 1)[0] for value in tmpfs if isinstance(value, str)
    }
    if not {"/tmp", "/dev/shm"}.issubset(tmpfs_targets):
        fail("biometric service requires private tmpfs at /tmp and /dev/shm")

    biometric_networks = service_network_names(biometric)
    if not biometric_networks:
        fail("biometric service has no internal network")
    for name in biometric_networks:
        network = networks.get(name)
        if not isinstance(network, dict) or network.get("internal") is not True:
            fail(f"biometric network {name!r} is not internal-only")

    print("canonical compose security gate: PASS")


if __name__ == "__main__":
    main()
