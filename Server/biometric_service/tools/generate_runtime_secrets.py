#!/usr/bin/env python3
"""Generate the raw runtime secrets used by the isolated biometric worker."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def create_exclusive(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    targets = [
        output_dir / "biometric_hmac.key",
        output_dir / "biometric_envelope_private.key",
        output_dir / "biometric_envelope_public.key",
    ]
    existing = [path.name for path in targets if path.exists()]
    if existing:
        parser.error(
            "refusing to overwrite existing secrets: " + ", ".join(existing)
        )

    private_key = X25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    create_exclusive(targets[0], os.urandom(32), 0o600)
    create_exclusive(targets[1], private_raw, 0o600)
    create_exclusive(targets[2], public_raw, 0o644)
    print(f"Created three runtime secrets in {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
