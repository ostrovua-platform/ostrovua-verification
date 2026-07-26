#!/usr/bin/env python3
"""Validate and aggregate a pseudonymous real-document test corpus.

The input deliberately contains no DG1/DG2 bytes, names, document numbers,
birth dates, images, signatures or raw APDU transcripts.  Each row is a
minimal receipt describing one consented lab run and binding it to hashes of
the server artifact and separately retained evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "ostrovua-document-corpus-v1"
REPORT_SCHEMA = "ostrovua-document-corpus-report-v1"
PROFILES = {"aa_rsa", "aa_ecdsa", "ca", "passive_only", "negative"}
OUTCOMES = {"auto_eligible", "pending_review", "reject"}
PASSIVE_RESULTS = {"passed", "failed"}
AA_RESULTS = {"rsa", "ecdsa", "not_supported", "failed"}
CA_RESULTS = {"passed", "not_supported", "failed"}
OPAQUE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
STATE_RE = re.compile(r"^[A-Z]{3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_FIELDS = {
    "schema",
    "caseId",
    "profile",
    "issuingState",
    "documentSeries",
    "deviceClass",
    "osClass",
    "expectedOutcome",
    "observedOutcome",
    "passiveAuthentication",
    "activeAuthentication",
    "chipAuthentication",
    "dg14Profile",
    "dg15Profile",
    "serverArtifactSha256",
    "evidenceSha256",
}


def _opaque(value: Any) -> bool:
    return isinstance(value, str) and OPAQUE_RE.fullmatch(value) is not None


def _validate_profile(row: dict[str, Any], index: int) -> None:
    profile = row["profile"]
    passive = row["passiveAuthentication"]
    active = row["activeAuthentication"]
    chip = row["chipAuthentication"]
    expected = row["expectedOutcome"]
    if profile == "aa_rsa" and not (passive == "passed" and active == "rsa"):
        raise ValueError(f"row {index}: aa_rsa_profile_inconsistent")
    if profile == "aa_ecdsa" and not (passive == "passed" and active == "ecdsa"):
        raise ValueError(f"row {index}: aa_ecdsa_profile_inconsistent")
    if profile == "ca" and not (passive == "passed" and chip == "passed"):
        raise ValueError(f"row {index}: ca_profile_inconsistent")
    if profile == "passive_only" and not (
        passive == "passed" and active == "not_supported" and chip == "not_supported"
        and expected == "pending_review"
    ):
        raise ValueError(f"row {index}: passive_only_profile_inconsistent")
    if profile == "negative" and expected != "reject":
        raise ValueError(f"row {index}: negative_profile_inconsistent")


def evaluate(rows: Iterable[dict[str, Any]], *, minimum_per_profile: int = 5,
             minimum_issuing_states: int = 2,
             minimum_series_per_profile: int = 2,
             expected_server_sha256: str | None = None) -> dict[str, Any]:
    if minimum_per_profile < 1 or minimum_issuing_states < 1 or \
       minimum_series_per_profile < 1:
        raise ValueError("requirements_invalid")
    if expected_server_sha256 is not None and \
       SHA256_RE.fullmatch(expected_server_sha256) is None:
        raise ValueError("expected_server_sha256_invalid")

    case_ids: set[str] = set()
    evidence_digests: set[str] = set()
    profile_counts: Counter[str] = Counter()
    issuing_states: set[str] = set()
    series_by_profile: dict[str, set[tuple[str, str]]] = defaultdict(set)
    device_classes: set[str] = set()
    os_classes: set[str] = set()
    server_artifacts: set[str] = set()
    mismatches = 0
    total = 0

    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or set(row) != EXPECTED_FIELDS:
            raise ValueError(f"row {index}: shape_invalid")
        if row["schema"] != SCHEMA:
            raise ValueError(f"row {index}: schema_invalid")
        for field in (
            "caseId", "documentSeries", "deviceClass", "osClass",
            "dg14Profile", "dg15Profile",
        ):
            if not _opaque(row[field]):
                raise ValueError(f"row {index}: {field}_invalid")
        if row["caseId"] in case_ids:
            raise ValueError(f"row {index}: case_id_duplicate")
        case_ids.add(row["caseId"])
        if row["profile"] not in PROFILES:
            raise ValueError(f"row {index}: profile_invalid")
        if not isinstance(row["issuingState"], str) or \
           STATE_RE.fullmatch(row["issuingState"]) is None:
            raise ValueError(f"row {index}: issuing_state_invalid")
        if row["expectedOutcome"] not in OUTCOMES or row["observedOutcome"] not in OUTCOMES:
            raise ValueError(f"row {index}: outcome_invalid")
        if row["passiveAuthentication"] not in PASSIVE_RESULTS or \
           row["activeAuthentication"] not in AA_RESULTS or \
           row["chipAuthentication"] not in CA_RESULTS:
            raise ValueError(f"row {index}: authentication_result_invalid")
        for field in ("serverArtifactSha256", "evidenceSha256"):
            if not isinstance(row[field], str) or SHA256_RE.fullmatch(row[field]) is None:
                raise ValueError(f"row {index}: {field}_invalid")
        if row["evidenceSha256"] in evidence_digests:
            raise ValueError(f"row {index}: evidence_digest_duplicate")
        evidence_digests.add(row["evidenceSha256"])
        _validate_profile(row, index)

        total += 1
        profile = row["profile"]
        profile_counts[profile] += 1
        issuing_states.add(row["issuingState"])
        series_by_profile[profile].add((row["issuingState"], row["documentSeries"]))
        device_classes.add(row["deviceClass"])
        os_classes.add(row["osClass"])
        server_artifacts.add(row["serverArtifactSha256"])
        mismatches += row["expectedOutcome"] != row["observedOutcome"]

    if total == 0:
        raise ValueError("corpus_empty")

    missing_profiles = sorted(PROFILES.difference(profile_counts))
    sample_gate = not missing_profiles and all(
        profile_counts[profile] >= minimum_per_profile for profile in PROFILES)
    diversity_gate = len(issuing_states) >= minimum_issuing_states and \
        not missing_profiles and all(
            len(series_by_profile[profile]) >= minimum_series_per_profile
            for profile in PROFILES)
    artifact_gate = len(server_artifacts) == 1 and (
        expected_server_sha256 is None or
        server_artifacts == {expected_server_sha256}
    )
    outcome_gate = mismatches == 0

    return {
        "schema": REPORT_SCHEMA,
        "counts": {
            "total": total,
            "profiles": {
                profile: profile_counts[profile] for profile in sorted(PROFILES)
            },
            "outcomeMismatches": mismatches,
        },
        "coverage": {
            "issuingStates": len(issuing_states),
            "seriesPerProfile": {
                profile: len(series_by_profile[profile])
                for profile in sorted(PROFILES)
            },
            "deviceClasses": len(device_classes),
            "osClasses": len(os_classes),
        },
        "requirements": {
            "requiredProfiles": sorted(PROFILES),
            "minimumPerProfile": minimum_per_profile,
            "minimumIssuingStates": minimum_issuing_states,
            "minimumSeriesPerProfile": minimum_series_per_profile,
        },
        "missingProfiles": missing_profiles,
        "sampleGatePassed": sample_gate,
        "diversityGatePassed": diversity_gate,
        "artifactGatePassed": artifact_gate,
        "outcomeGatePassed": outcome_gate,
        "approved": sample_gate and diversity_gate and artifact_gate and outcome_gate,
        "privacy": {
            "containsRawDocumentData": False,
            "containsRawBiometrics": False,
            "containsRawTranscripts": False,
        },
    }


def read_jsonl(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    source = path.read_bytes()
    if len(source) == 0 or len(source) > 10 * 1024 * 1024:
        raise ValueError("source_size_invalid")
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(source.splitlines(), 1):
        if not raw_line.strip():
            continue
        if len(raw_line) > 16 * 1024:
            raise ValueError(f"line {line_number}: line_too_large")
        try:
            rows.append(json.loads(raw_line))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"line {line_number}: invalid_json") from error
    return source, rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--minimum-per-profile", type=int, default=5)
    parser.add_argument("--minimum-issuing-states", type=int, default=2)
    parser.add_argument("--minimum-series-per-profile", type=int, default=2)
    parser.add_argument("--expected-server-sha256")
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()

    source, rows = read_jsonl(args.input)
    report = evaluate(
        rows,
        minimum_per_profile=args.minimum_per_profile,
        minimum_issuing_states=args.minimum_issuing_states,
        minimum_series_per_profile=args.minimum_series_per_profile,
        expected_server_sha256=args.expected_server_sha256,
    )
    report["sourceSha256"] = hashlib.sha256(source).hexdigest()
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 1 if args.require_pass and not report["approved"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
