#!/usr/bin/env python3
"""Produce a reproducible, image-free biometric/PAD calibration report.

Input is JSON Lines containing pseudonymous, transaction-level score series.
Every metric is derived through the same deterministic ``policy.decide``
function used by the production worker.  The report stores only aggregate
counts and a SHA-256 of the source file, never images, embeddings or
per-person identifiers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from policy import POLICY_VERSION, decide, policy_parameters


Z_95 = 1.959963984540054
ALLOWED_CATEGORIES = {"genuine_face", "impostor_face", "bona_fide_pad", "attack_pad"}
ALLOWED_ATTACKS = {"print", "screen", "mask", "injection", "deepfake"}
SUBJECT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TRIAL_RE = re.compile(r"^[A-Za-z0-9_-]{1,96}$")
BASE_TRANSACTION_FIELDS = {
    "category",
    "trial",
    "subject",
    "neutralFaceScores",
    "challengeFaceScores",
    "padScores",
    "qualityPassed",
    "depthPassed",
    "challengePassed",
}


def wilson(errors: int, total: int) -> tuple[float, float]:
    if total <= 0 or errors < 0 or errors > total:
        raise ValueError("invalid binomial sample")
    rate = errors / total
    denominator = 1 + Z_95 * Z_95 / total
    center = (rate + Z_95 * Z_95 / (2 * total)) / denominator
    margin = Z_95 * math.sqrt(
        rate * (1 - rate) / total + Z_95 * Z_95 / (4 * total * total)
    ) / denominator
    low = 0.0 if errors == 0 else max(0.0, center - margin)
    high = 1.0 if errors == total else min(1.0, center + margin)
    return low, high


def metric(errors: int, total: int) -> dict[str, Any]:
    low, high = wilson(errors, total)
    return {"errors": errors, "total": total, "rate": errors / total, "ci95": [low, high]}


def _score_series(row: dict[str, Any], field: str, *, minimum: int, maximum: int,
                  low: float, high: float, index: int) -> list[float]:
    values = row.get(field)
    if not isinstance(values, list) or not minimum <= len(values) <= maximum:
        raise ValueError(f"row {index}: {field}_shape_invalid")
    if any(not isinstance(value, (int, float)) or isinstance(value, bool) or
           not math.isfinite(value) or not low <= float(value) <= high
           for value in values):
        raise ValueError(f"row {index}: {field}_value_invalid")
    return [float(value) for value in values]


def _transaction_decision(neutral: list[float], challenge: list[float],
                          pad: list[float], quality: bool, depth: bool,
                          active_challenge: bool) -> bool:
    decision, _reason = decide(
        neutral_face_scores=neutral,
        challenge_face_scores=challenge,
        pad_scores=pad,
        challenge_passed=active_challenge,
        quality_passed=quality,
        depth_passed=depth,
        calibration_approved=True,
    )
    return decision == "passed"


def _face_component_decision(neutral: list[float], challenge: list[float]) -> bool:
    return _transaction_decision(
        neutral,
        challenge,
        [1.0] * len(challenge),
        True,
        True,
        True,
    )


def _pad_component_decision(neutral_count: int, challenge_count: int,
                            pad: list[float], quality: bool, depth: bool,
                            active_challenge: bool) -> bool:
    return _transaction_decision(
        [1.0] * neutral_count,
        [1.0] * challenge_count,
        pad,
        quality,
        depth,
        active_challenge,
    )


def evaluate(rows: Iterable[dict[str, Any]], *,
             minimum_genuine: int = 30, minimum_impostor: int = 100,
             minimum_bona_fide: int = 30, minimum_attack: int = 35,
             minimum_genuine_subjects: int = 10,
             minimum_impostor_subjects: int = 10,
             minimum_impostor_pairs: int = 50,
             minimum_bona_fide_subjects: int = 10,
             minimum_attack_subjects: int = 5,
             maximum_fnmr_upper: float = 0.20, maximum_fmr_upper: float = 0.05,
             maximum_bpcer_upper: float = 0.20,
             maximum_apcer_upper: float = 0.10) -> dict[str, Any]:
    genuine: list[bool] = []
    impostor: list[bool] = []
    bona_fide: list[bool] = []
    attacks: dict[str, list[bool]] = defaultdict(list)
    genuine_transactions: list[bool] = []
    impostor_transactions: list[bool] = []
    bona_fide_transactions: list[bool] = []
    attack_transactions: dict[str, list[bool]] = defaultdict(list)
    genuine_subjects: set[str] = set()
    impostor_subjects: set[str] = set()
    impostor_pairs: set[tuple[str, str]] = set()
    bona_fide_subjects: set[str] = set()
    attack_subjects: dict[str, set[str]] = defaultdict(set)
    trials: set[str] = set()

    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("category") not in ALLOWED_CATEGORIES:
            raise ValueError(f"row {index}: category_invalid")
        category = row["category"]
        expected = set(BASE_TRANSACTION_FIELDS)
        if category == "impostor_face":
            expected.add("comparisonSubject")
        elif category == "attack_pad":
            expected.add("attack")
        if set(row) != expected:
            raise ValueError(f"row {index}: shape_invalid")
        trial = row["trial"]
        if not isinstance(trial, str) or TRIAL_RE.fullmatch(trial) is None or trial in trials:
            raise ValueError(f"row {index}: trial_invalid")
        trials.add(trial)
        subject = row["subject"]
        if not isinstance(subject, str) or SUBJECT_RE.fullmatch(subject) is None:
            raise ValueError(f"row {index}: subject_invalid")
        neutral = _score_series(
            row, "neutralFaceScores", minimum=3, maximum=5,
            low=-1.0, high=1.0, index=index)
        challenge = _score_series(
            row, "challengeFaceScores", minimum=12, maximum=24,
            low=-1.0, high=1.0, index=index)
        pad = _score_series(
            row, "padScores", minimum=12, maximum=24,
            low=0.0, high=1.0, index=index)
        if len(challenge) != len(pad):
            raise ValueError(f"row {index}: challenge_series_length_mismatch")
        for field in ("qualityPassed", "depthPassed", "challengePassed"):
            if not isinstance(row[field], bool):
                raise ValueError(f"row {index}: {field}_invalid")
        full_accepted = _transaction_decision(
            neutral,
            challenge,
            pad,
            row["qualityPassed"],
            row["depthPassed"],
            row["challengePassed"],
        )
        face_accepted = _face_component_decision(neutral, challenge)
        pad_accepted = _pad_component_decision(
            len(neutral),
            len(challenge),
            pad,
            row["qualityPassed"],
            row["depthPassed"],
            row["challengePassed"],
        )
        if category == "genuine_face":
            genuine.append(face_accepted)
            genuine_transactions.append(full_accepted)
            genuine_subjects.add(subject)
        elif category == "impostor_face":
            comparison_subject = row["comparisonSubject"]
            if not isinstance(comparison_subject, str) or \
               SUBJECT_RE.fullmatch(comparison_subject) is None or \
               comparison_subject == subject:
                raise ValueError(f"row {index}: comparison_subject_invalid")
            impostor.append(face_accepted)
            impostor_transactions.append(full_accepted)
            impostor_subjects.update((subject, comparison_subject))
            impostor_pairs.add(tuple(sorted((subject, comparison_subject))))
        elif category == "bona_fide_pad":
            bona_fide.append(pad_accepted)
            bona_fide_transactions.append(full_accepted)
            bona_fide_subjects.add(subject)
        else:
            attack = row["attack"]
            if attack not in ALLOWED_ATTACKS:
                raise ValueError(f"row {index}: attack_invalid")
            attacks[attack].append(pad_accepted)
            attack_transactions[attack].append(full_accepted)
            attack_subjects[attack].add(subject)

    if not genuine or not impostor or not bona_fide or not attacks:
        raise ValueError("required_classes_missing")

    metrics = {
        "fnmr": metric(sum(not accepted for accepted in genuine), len(genuine)),
        "fmr": metric(sum(impostor), len(impostor)),
        "bpcer": metric(sum(not accepted for accepted in bona_fide), len(bona_fide)),
        "apcer": {
            attack: metric(sum(accepted for accepted in decisions), len(decisions))
            for attack, decisions in sorted(attacks.items())
        },
    }
    transaction_metrics = {
        "genuineFalseReject": metric(
            sum(not accepted for accepted in genuine_transactions),
            len(genuine_transactions),
        ),
        "impostorFalseAccept": metric(
            sum(impostor_transactions),
            len(impostor_transactions),
        ),
        "bonaFideFalseReject": metric(
            sum(not accepted for accepted in bona_fide_transactions),
            len(bona_fide_transactions),
        ),
        "attackFalseAccept": {
            attack: metric(
                sum(attack_transactions[attack]),
                len(attack_transactions[attack]),
            )
            for attack in sorted(attack_transactions)
        },
    }
    missing_attacks = sorted(ALLOWED_ATTACKS.difference(attacks))
    sample_gate = not missing_attacks and \
        len(genuine) >= minimum_genuine and len(impostor) >= minimum_impostor and \
        len(bona_fide) >= minimum_bona_fide and \
        all(len(attacks[attack]) >= minimum_attack for attack in ALLOWED_ATTACKS)
    diversity_gate = len(genuine_subjects) >= minimum_genuine_subjects and \
        len(impostor_subjects) >= minimum_impostor_subjects and \
        len(impostor_pairs) >= minimum_impostor_pairs and \
        len(bona_fide_subjects) >= minimum_bona_fide_subjects and \
        all(len(attack_subjects[attack]) >= minimum_attack_subjects
            for attack in ALLOWED_ATTACKS)
    accuracy_gate = metrics["fnmr"]["ci95"][1] <= maximum_fnmr_upper and \
        metrics["fmr"]["ci95"][1] <= maximum_fmr_upper and \
        metrics["bpcer"]["ci95"][1] <= maximum_bpcer_upper and \
        all(value["ci95"][1] <= maximum_apcer_upper for value in metrics["apcer"].values())
    return {
        "schema": "ostrovua-biometric-evaluation-v3",
        "policyParameters": policy_parameters(),
        "metrics": metrics,
        "transactionMetrics": transaction_metrics,
        "cohortDiversity": {
            "genuineSubjects": len(genuine_subjects),
            "impostorSubjects": len(impostor_subjects),
            "impostorPairs": len(impostor_pairs),
            "bonaFideSubjects": len(bona_fide_subjects),
            "attackSubjects": {
                attack: len(attack_subjects[attack]) for attack in sorted(ALLOWED_ATTACKS)
            },
        },
        "requirements": {
            "minimumSamples": {
                "genuine": minimum_genuine,
                "impostor": minimum_impostor,
                "bonaFide": minimum_bona_fide,
                "perAttack": minimum_attack,
            },
            "minimumSubjects": {
                "genuine": minimum_genuine_subjects,
                "impostor": minimum_impostor_subjects,
                "impostorPairs": minimum_impostor_pairs,
                "bonaFide": minimum_bona_fide_subjects,
                "perAttack": minimum_attack_subjects,
            },
            "requiredAttacks": sorted(ALLOWED_ATTACKS),
            "maximumCi95Upper": {
                "fnmr": maximum_fnmr_upper,
                "fmr": maximum_fmr_upper,
                "bpcer": maximum_bpcer_upper,
                "apcerPerAttack": maximum_apcer_upper,
            },
        },
        "missingAttacks": missing_attacks,
        "sampleGatePassed": sample_gate,
        "diversityGatePassed": diversity_gate,
        "accuracyGatePassed": accuracy_gate,
        "approved": sample_gate and diversity_gate and accuracy_gate,
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise ValueError(f"line {line_number}: invalid_json") from error
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-pass", action="store_true")
    args = parser.parse_args()
    source = args.input.read_bytes()
    report = evaluate(read_jsonl(args.input))
    manifest = json.loads((Path(__file__).resolve().parent / "model_manifest.json").read_text(encoding="utf-8"))
    canonical_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    report["policyVersion"] = POLICY_VERSION
    report["modelSetHash"] = hashlib.sha256(canonical_manifest).hexdigest()
    report["sourceSha256"] = hashlib.sha256(source).hexdigest()
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 1 if args.require_pass and not report["approved"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
