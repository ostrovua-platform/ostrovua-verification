"""Fail-closed verification of an independently signed aggregate report."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from policy import POLICY_VERSION, policy_parameters


REQUIRED_CALIBRATION_ATTACKS = ["deepfake", "injection", "mask", "print", "screen"]


def _canonical_base64(value: str, expected_size: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a string")
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != expected_size or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("not canonical")
    return decoded


def verify_calibration_report(report_bytes: bytes, expected_id: str,
                              expected_model_hash: str, public_key_b64: str,
                              signature_b64: str) -> bool:
    try:
        if len(report_bytes) == 0 or len(report_bytes) > 1024 * 1024 or \
           re.fullmatch(r"[0-9a-f]{64}", expected_id) is None or \
           hashlib.sha256(report_bytes).hexdigest() != expected_id:
            return False
        public_key = _canonical_base64(public_key_b64, 32)
        signature = _canonical_base64(signature_b64, 64)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, report_bytes)
        report = json.loads(report_bytes)
        requirements = report.get("requirements") if isinstance(report, dict) else None
        return report.get("schema") == "ostrovua-biometric-evaluation-v3" and \
            report.get("policyVersion") == POLICY_VERSION and \
            report.get("policyParameters") == policy_parameters() and \
            report.get("modelSetHash") == expected_model_hash and \
            isinstance(report.get("metrics"), dict) and \
            isinstance(report.get("transactionMetrics"), dict) and \
            re.fullmatch(r"[0-9a-f]{64}", report.get("sourceSha256", "")) is not None and \
            report.get("approved") is True and \
            report.get("sampleGatePassed") is True and \
            report.get("diversityGatePassed") is True and \
            report.get("accuracyGatePassed") is True and \
            report.get("missingAttacks") == [] and \
            isinstance(requirements, dict) and \
            requirements.get("requiredAttacks") == REQUIRED_CALIBRATION_ATTACKS
    except (InvalidSignature, ValueError, TypeError, json.JSONDecodeError):
        return False


def calibration_is_approved(model_set_hash: str) -> bool:
    if os.environ.get("BIOMETRIC_CALIBRATION_APPROVED") != "1":
        return False
    try:
        report_bytes = Path(os.environ["BIOMETRIC_CALIBRATION_REPORT"]).read_bytes()
        return verify_calibration_report(
            report_bytes,
            os.environ.get("BIOMETRIC_CALIBRATION_ID", "").strip(),
            model_set_hash,
            os.environ.get("BIOMETRIC_CALIBRATION_PUBLIC_KEY", ""),
            os.environ.get("BIOMETRIC_CALIBRATION_SIGNATURE", ""),
        )
    except (KeyError, OSError):
        return False
