#!/usr/bin/env python3
"""Overlay reviewed verification-v7 code onto the current production-v6 tree.

The production backend intentionally remains on its existing Hasura/PgBouncer
topology during dark deployment. All database calls introduced by this slice
go through production_verification_store.js, whose inputs are independently
typed and allowlisted before a fixed SECURITY DEFINER invocation is built.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[1]


def region(text: str, start: str, end: str) -> tuple[int, int]:
    start_offset = text.find(start)
    end_offset = text.find(end, start_offset + len(start))
    if start_offset < 0 or end_offset < 0:
        raise RuntimeError(f"missing integration marker: {start!r} / {end!r}")
    if text.find(start, start_offset + len(start)) >= 0:
        raise RuntimeError(f"ambiguous integration marker: {start!r}")
    return start_offset, end_offset


def replace_region(
    target: str,
    source: str,
    target_start: str,
    target_end: str,
    source_start: str | None = None,
    source_end: str | None = None,
) -> str:
    target_offsets = region(target, target_start, target_end)
    source_offsets = region(
        source,
        source_start or target_start,
        source_end or target_end,
    )
    return (
        target[: target_offsets[0]]
        + source[source_offsets[0] : source_offsets[1]]
        + target[target_offsets[1] :]
    )


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def replace_through(text: str, start: str, end: str, replacement: str) -> str:
    start_offset = text.find(start)
    end_offset = text.find(end, start_offset + len(start))
    if start_offset < 0 or end_offset < 0:
        raise RuntimeError(f"missing block marker: {start!r} / {end!r}")
    end_offset += len(end)
    return text[:start_offset] + replacement + text[end_offset:]


def copy_tree(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
    )


def production_approval_source(reference: str) -> str:
    start, end = region(
        reference,
        "function isValidDgHashes",
        "// END PROTOCOL V7 VERIFICATION ROUTES",
    )
    approval = reference[start:end]

    pepper_block = """  const DOC_PEPPER = process.env.DOC_TOKEN_PEPPER || '';
  const LEGACY_DOC_PEPPER = process.env.DOC_TOKEN_PEPPER_PREVIOUS || '';
  if (!DOC_PEPPER) {
"""
    pepper_replacement = """  if (!DOC_TOKEN_PEPPER) {
"""
    approval = replace_once(
        approval,
        pepper_block,
        pepper_replacement,
        "file-backed document pepper",
    ).replace("DOC_PEPPER", "DOC_TOKEN_PEPPER")

    activation_start = """      const result = await db.pool.query(
        `SELECT activate_self_hosted_verified_id_v7_rotating("""
    activation_end = "      const outcome = result.rows?.[0]?.outcome;"
    activation_replacement = """      const outcome = await verificationStore.activateSelfHostedV7({
        documentToken: docToken,
        legacyDocumentToken: legacyDocToken,
        contributorId,
        requestId: receipt.requestId,
        policyVersion: receipt.policyVersion,
        modelSetHash: receipt.modelSetHash,
        receiptDigest: receipt.receiptDigest,
        receiptSignature: receipt.receiptSignature,
        serviceTimestamp: receipt.receiptTimestamp,
        protocolVersion,
        documentAssurance,
      });"""
    approval = replace_through(
        approval,
        activation_start,
        activation_end,
        activation_replacement,
    )

    review_start = """    const result = await db.pool.query(
      `SELECT submit_verification_review_v7_rotating("""
    review_end = "    const outcome = result.rows?.[0]?.outcome;"
    review_replacement = """    const outcome = await verificationStore.submitReviewV7({
      documentToken: docToken,
      legacyDocumentToken: legacyDocToken,
      contributorId,
      faceModel: b.faceModel,
      faceModelVersion: b.faceModelVersion,
      faceScore: b.faceScore,
      faceThreshold: b.faceThreshold,
      faceSampleCount: b.faceSampleCount,
      faceContinuityScore: b.faceContinuityScore,
      livenessFrameCount: b.livenessFrameCount,
      livenessDurationMs: b.livenessDurationMs,
      protocolVersion: b.protocolVersion,
      documentAssurance,
    });"""
    return replace_through(
        approval,
        review_start,
        review_end,
        review_replacement,
    )


def integrate(target_backend: Path) -> Path:
    auth = target_backend / "auth"
    server_path = auth / "server.js"
    dockerfile_path = auth / "Dockerfile"
    if not server_path.is_file() or not dockerfile_path.is_file():
        raise RuntimeError("target must contain auth/server.js and auth/Dockerfile")

    current = server_path.read_text(encoding="utf-8")
    policy = (auth / "verification_policy.js").read_text(encoding="utf-8")
    if "const PROTOCOL_VERSION = 6;" not in policy or \
       "LEGACY_REVIEW_PROTOCOL_VERSION" not in current:
        raise RuntimeError("target is not the reviewed production-v6 baseline")

    reference = (SERVER_ROOT / "verify_approve.route.js").read_text(encoding="utf-8")

    limiter = """function rlKeyValid(key) {
  return /^acct:[0-9a-fA-F-]{36}$/.test(key) ||
    /^dev:[A-Za-z0-9+/=_-]{1,64}$/.test(key);
}
async function rlQuery(functionName, key) {
  if (!rlKeyValid(key)) throw new Error('verification_rate_limit_key_invalid');
  return verificationStore.rateLimit(functionName, key);
}
const rlTouch = (key) => rlQuery('rl_touch', key);
const rlCheck = (key) => rlQuery('rl_check', key);
async function rlReset(key) {
  if (!rlKeyValid(key)) throw new Error('verification_rate_limit_key_invalid');
  await verificationStore.resetRateLimit(key);
}
function rlKeysFor(contributorId, req) {
  const keys = [];
  if (/^[0-9a-fA-F-]{36}$/.test(contributorId || '')) {
    keys.push(`acct:${contributorId}`);
  }
  const device = req.headers['x-attest-key'];
  if (typeof device === 'string' && /^[A-Za-z0-9+/=_-]{1,64}$/.test(device)) {
    keys.push(`dev:${device}`);
  }
  if (keys.length !== 2) {
    throw new Error('verification_rate_limit_identity_incomplete');
  }
  return keys;
}
function rlLockedMessage(until) {
  const milliseconds = until ? new Date(until).getTime() - Date.now() : 0;
  if (milliseconds > 300 * 24 * 3600e3) {
    return 'Верифікацію заблоковано за підозрілу активність. Звернись у підтримку (апеляція).';
  }
  const hours = Math.ceil(milliseconds / 3600e3);
  const when = hours >= 24
    ? `${Math.ceil(hours / 24)} дн.`
    : `${Math.max(1, hours)} год.`;
  return `Забагато спроб верифікації. Спробуй за ${when}.`;
}

"""
    limiter_start, limiter_end = region(
        current,
        "function rlKeyValid",
        "// ── FIND OR CREATE CONTRIBUTOR",
    )
    current = current[:limiter_start] + limiter + current[limiter_end:]

    current = replace_region(
        current,
        reference,
        "app.post('/auth/verify/challenge'",
        "// Реєстрація ключа пристрою",
        source_end="async function verifyAppAttestAssertion",
    )

    approval_start, approval_end = region(
        current,
        "function isValidDgHashes",
        "//  СПОВІЩЕННЯ (push)",
    )
    current = (
        current[:approval_start]
        + production_approval_source(reference)
        + current[approval_end:]
    )

    imports = """const biometricClient = require('./biometric_client');"""
    imports_v7 = """const biometricClient = require('./biometric_client');
const {
  createProductionVerificationStore,
} = require('./production_verification_store');
const verificationStore = createProductionVerificationStore(hasuraSQL);"""
    current = replace_once(current, imports, imports_v7, "verification store import")

    required = [
        "PROTOCOL_VERSION",
        "documentAuthenticationChallengeId",
        "activateSelfHostedV7",
        "submitReviewV7",
        "DOC_TOKEN_PEPPER",
    ]
    if any(value not in current for value in required) or \
       "LEGACY_REVIEW_PROTOCOL_VERSION" in current or \
       "db.pool" in current:
        raise RuntimeError("production-v7 postcondition failed")

    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = server_path.with_name(f"server.js.pre-v7.{timestamp}")
    backup.write_bytes(server_path.read_bytes())
    server_path.write_text(current, encoding="utf-8")

    for name in (
        "appattest.js",
        "passiveauth.js",
        "verification_policy.js",
        "self_hosted_contract.js",
        "biometric_client.js",
        "production_verification_store.js",
    ):
        shutil.copy2(SERVER_ROOT / name, auth / name)

    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    dockerfile = replace_once(
        dockerfile,
        """COPY server.js appattest.js apns.js passiveauth.js verification_policy.js \\
     self_hosted_contract.js biometric_client.js ./""",
        """COPY server.js appattest.js apns.js passiveauth.js verification_policy.js \\
     self_hosted_contract.js biometric_client.js \\
     production_verification_store.js ./""",
        "production Dockerfile module list",
    )
    dockerfile_path.write_text(dockerfile, encoding="utf-8")

    copy_tree(
        SERVER_ROOT / "biometric_service",
        auth / "biometric_service",
    )
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
    print(f"production-v7 slice installed; rollback backup: {backup}")


if __name__ == "__main__":
    main()
