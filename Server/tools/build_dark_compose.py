#!/usr/bin/env python3
"""Build a fail-closed, digest-pinned production dark-deploy compose file."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import yaml


DIGEST_IMAGE = re.compile(r"^[^\s@]+(?:/[^\s@]+)*@sha256:[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(f"dark compose builder: {message}")


def environment(service: dict) -> dict[str, str]:
    current = service.get("environment", {})
    if not isinstance(current, dict):
        fail("service environment must use mapping form")
    return {str(key): str(value) for key, value in current.items()}


def volume_target(value: object) -> str:
    if isinstance(value, str):
        fields = value.split(":")
        return fields[1] if len(fields) >= 2 else ""
    if isinstance(value, dict):
        return str(value.get("target", ""))
    return ""


def secret_mount(source: str, target: str) -> dict[str, str]:
    return {"source": source, "target": target}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("images", type=Path)
    parser.add_argument("--envelope-key-id", required=True)
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-f]{64}", args.envelope_key_id):
        fail("envelope key id must be lowercase SHA-256")

    try:
        config = yaml.safe_load(args.source.read_text(encoding="utf-8"))
        image_map = json.loads(args.images.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, yaml.YAMLError) as error:
        fail(f"cannot read input: {error}")
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        fail("source compose has no services mapping")
    services = config["services"]
    if set(image_map) != set(services):
        fail(
            "image map must match services exactly: "
            f"services={sorted(services)} images={sorted(image_map)}"
        )
    for name, image in image_map.items():
        if not isinstance(image, str) or not DIGEST_IMAGE.fullmatch(image):
            fail(f"image for {name!r} is not digest-pinned")
        service = services[name]
        if not isinstance(service, dict):
            fail(f"service {name!r} is not a mapping")
        service["image"] = image
        service.pop("build", None)
        if name != "nginx":
            service.pop("ports", None)

    auth = services.get("auth")
    biometric = services.get("biometric")
    if not isinstance(auth, dict) or not isinstance(biometric, dict):
        fail("auth and biometric services are required")

    auth_env = environment(auth)
    auth_env.update(
        {
            "APP_ENV": "production",
            "SELF_HOSTED_VERIFICATION_ENABLED": "0",
            "BIOMETRIC_SHADOW_MODE_ENABLED": "0",
            "BIOMETRIC_SHADOW_TESTER_IDS": "",
            "BIOMETRIC_CALIBRATION_APPROVED": "0",
            "SERVER_OWNED_CA_ENABLED": "0",
            "AUTH_SESSION_ENFORCEMENT_ENABLED": "0",
            "BIOMETRIC_SERVICE_URL": "http://biometric:8080/v1/verify",
            "BIOMETRIC_HMAC_SECRET_FILE": "/run/secrets/biometric_hmac.key",
            "BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE":
                "/run/secrets/biometric_envelope_public.key",
            "BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256": args.envelope_key_id,
            "DOCUMENT_CA_SEALING_KEY_FILE":
                "/run/secrets/document_ca_sealing.key",
            "AUTH_RATE_LIMIT_PEPPER_FILE":
                "/run/secrets/auth_rate_limit_pepper.key",
            "AUTH_SESSION_METADATA_PEPPER_FILE":
                "/run/secrets/auth_session_metadata_pepper.key",
            "PASSWORD_RESET_PEPPER_FILE":
                "/run/secrets/password_reset_pepper.key",
        }
    )
    auth["environment"] = auth_env
    auth["volumes"] = [
        value
        for value in auth.get("volumes", [])
        if volume_target(value) not in {"/run/biometric-secrets", "/run/secrets"}
    ]
    auth["secrets"] = [
        secret_mount("doc_token_pepper_current", "doc_token_pepper_current"),
        secret_mount("doc_token_pepper_previous", "doc_token_pepper_previous"),
        secret_mount("biometric_hmac", "biometric_hmac.key"),
        secret_mount(
            "biometric_envelope_public", "biometric_envelope_public.key"
        ),
        secret_mount("document_ca_sealing", "document_ca_sealing.key"),
        secret_mount("auth_rate_limit_pepper", "auth_rate_limit_pepper.key"),
        secret_mount(
            "auth_session_metadata_pepper", "auth_session_metadata_pepper.key"
        ),
        secret_mount("password_reset_pepper", "password_reset_pepper.key"),
    ]

    biometric_env = environment(biometric)
    biometric_env.update(
        {
            "APP_ENV": "production",
            "BIOMETRIC_CALIBRATION_APPROVED": "0",
            "BIOMETRIC_HMAC_SECRET_FILE": "/run/secrets/biometric_hmac.key",
            "BIOMETRIC_ENVELOPE_PRIVATE_KEY_FILE":
                "/run/secrets/biometric_envelope_private.key",
            "BIOMETRIC_ENVELOPE_ACTIVE_KEY_SHA256": args.envelope_key_id,
        }
    )
    biometric_env.pop("BIOMETRIC_ENVELOPE_SECONDARY_PRIVATE_KEY_FILE", None)
    biometric_env.pop("BIOMETRIC_ENVELOPE_SECONDARY_KEY_SHA256", None)
    biometric["environment"] = biometric_env
    biometric["volumes"] = [
        {
            "type": "bind",
            "source": "./auth/biometric_calibration",
            "target": "/run/calibration",
            "read_only": True,
        }
    ]
    biometric["secrets"] = [
        secret_mount("biometric_hmac", "biometric_hmac.key"),
        secret_mount(
            "biometric_envelope_private", "biometric_envelope_private.key"
        ),
    ]
    biometric["read_only"] = True
    biometric["tmpfs"] = [
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "/dev/shm:rw,noexec,nosuid,nodev,size=256m",
    ]
    biometric.pop("shm_size", None)
    biometric["cap_drop"] = ["ALL"]
    biometric["security_opt"] = ["no-new-privileges:true"]
    biometric["pids_limit"] = 64
    biometric["mem_limit"] = "2g"
    biometric["memswap_limit"] = "2g"
    biometric["ulimits"] = {"core": {"soft": 0, "hard": 0}}

    config["secrets"] = {
        "doc_token_pepper_current": {
            "file": "/etc/ostrovua/secrets/doc_token_pepper.current"
        },
        "doc_token_pepper_previous": {
            "file": "/etc/ostrovua/secrets/doc_token_pepper.previous"
        },
        "biometric_hmac": {
            "file": "/etc/ostrovua/secrets/biometric_hmac.key"
        },
        "biometric_envelope_public": {
            "file": "/etc/ostrovua/secrets/biometric_envelope_public.key"
        },
        "biometric_envelope_private": {
            "file": "/etc/ostrovua/secrets/biometric_envelope_private.key"
        },
        "document_ca_sealing": {
            "file": "/etc/ostrovua/secrets/document_ca_sealing.key"
        },
        "auth_rate_limit_pepper": {
            "file": "/etc/ostrovua/secrets/auth_rate_limit_pepper.key"
        },
        "auth_session_metadata_pepper": {
            "file": "/etc/ostrovua/secrets/auth_session_metadata_pepper.key"
        },
        "password_reset_pepper": {
            "file": "/etc/ostrovua/secrets/password_reset_pepper.key"
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(config, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    print(f"dark compose written: {args.output}")


if __name__ == "__main__":
    main()
