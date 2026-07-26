#!/usr/bin/env python3
"""Install the reviewed protocol-v7 verification slice into the real backend.

The integration is deliberately marker-based and fail-closed: an unexpected
backend layout aborts before writing. A byte-for-byte server.js backup is kept
next to the target for rollback. Secrets and environment files are never read.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[1]


def replace_region(
    text: str,
    replacement_source: str,
    start: str,
    end: str,
    source_end: str | None = None,
) -> str:
    target_start = text.find(start)
    target_end = text.find(end, target_start + len(start))
    source_start = replacement_source.find(start)
    source_end_marker = source_end or end
    source_end_offset = replacement_source.find(
        source_end_marker, source_start + len(start)
    )
    if min(target_start, target_end, source_start, source_end_offset) < 0:
        raise RuntimeError(f"integration marker missing: {start!r} / {end!r}")
    if text.find(start, target_start + len(start)) >= 0:
        raise RuntimeError(f"target marker is ambiguous: {start!r}")
    return (
        text[:target_start]
        + replacement_source[source_start:source_end_offset]
        + text[target_end:]
    )


def replace_exactly_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"{label}: expected exactly one target, found {text.count(old)}")
    return text.replace(old, new, 1)


def copy_tree(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
    )


def integrate(target_backend: Path) -> Path:
    auth = target_backend / "auth"
    server_path = auth / "server.js"
    dockerfile_path = auth / "Dockerfile"
    if not server_path.is_file() or not dockerfile_path.is_file():
        raise RuntimeError("target must contain auth/server.js and auth/Dockerfile")

    current = server_path.read_text(encoding="utf-8")
    reference = (SERVER_ROOT / "verify_approve.route.js").read_text(encoding="utf-8")
    if "protocolVersion !== 4" not in current:
        raise RuntimeError("target is not the reviewed protocol-v4 baseline")

    parser_old = """const bigJson   = express.json({ limit: '40mb',  verify: captureRaw });
const smallJson = express.json({ limit: '512kb', verify: captureRaw });
app.use((req, res, next) =>
  (req.path === '/auth/upload' ? bigJson : smallJson)(req, res, next));"""
    parser_new = """const bigJson    = express.json({ limit: '40mb',  verify: captureRaw });
const verifyJson = express.json({ limit: '12mb', verify: captureRaw });
const smallJson  = express.json({ limit: '512kb', verify: captureRaw });
app.use((req, res, next) => {
  const parser = req.path === '/auth/upload'
    ? bigJson
    : (req.path === '/auth/verify/approve' ? verifyJson : smallJson);
  return parser(req, res, next);
});"""
    current = replace_exactly_once(current, parser_old, parser_new, "JSON parser")

    imports_old = """const appattest = require('./appattest');
const passiveauth = require('./passiveauth');"""
    imports_new = """const appattest = require('./appattest');
const passiveauth = require('./passiveauth');
const verificationPolicy = require('./verification_policy');
const { parseSelfHostedEnvelope } = require('./self_hosted_contract');
const biometricClient = require('./biometric_client');"""
    current = replace_exactly_once(current, imports_old, imports_new, "v7 imports")

    current = replace_region(
        current,
        reference,
        "app.post('/auth/verify/challenge'",
        "// Реєстрація ключа пристрою",
        "async function verifyAppAttestAssertion",
    )
    current = replace_region(
        current,
        reference,
        "function isValidDgHashes",
        "//  СПОВІЩЕННЯ (push)",
        "// END PROTOCOL V7 VERIFICATION ROUTES",
    )

    if "verificationPolicy.PROTOCOL_VERSION" not in current or \
       "activate_self_hosted_verified_id_v7_rotating" not in current or \
       "protocolVersion !== 4" in current:
        raise RuntimeError("protocol-v7 postcondition failed")

    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = server_path.with_name(f"server.js.pre-v7.{timestamp}")
    backup.write_bytes(server_path.read_bytes())
    server_path.write_text(current, encoding="utf-8")

    for name in (
        "passiveauth.js",
        "verification_policy.js",
        "self_hosted_contract.js",
        "biometric_client.js",
        "validate_dsc_chain.js",
    ):
        shutil.copy2(SERVER_ROOT / name, auth / name)

    copy_tree(SERVER_ROOT / "biometric_service", target_backend / "biometric_service")
    migrations = target_backend / "db" / "migrations"
    migrations.mkdir(parents=True, exist_ok=True)
    for migration in sorted((SERVER_ROOT / "migrations").glob("*.sql")):
        shutil.copy2(migration, migrations / migration.name)

    return backup


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target_backend", type=Path)
    args = parser.parse_args()
    backup = integrate(args.target_backend.resolve())
    print(f"protocol-v7 backend slice installed; rollback backup: {backup}")


if __name__ == "__main__":
    main()
