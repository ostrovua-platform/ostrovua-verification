import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE))

from calibration import verify_calibration_report  # noqa: E402
from policy import POLICY_VERSION, policy_parameters  # noqa: E402


class CalibrationReportTests(unittest.TestCase):
    model_hash = "a" * 64

    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        public = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.public_b64 = base64.b64encode(public).decode("ascii")

    def report_bytes(self, **overrides):
        report = {
            "schema": "ostrovua-biometric-evaluation-v3",
            "policyVersion": POLICY_VERSION,
            "policyParameters": policy_parameters(),
            "modelSetHash": self.model_hash,
            "sourceSha256": "b" * 64,
            "metrics": {},
            "transactionMetrics": {},
            "approved": True,
            "sampleGatePassed": True,
            "diversityGatePassed": True,
            "accuracyGatePassed": True,
            "missingAttacks": [],
            "requirements": {
                "requiredAttacks": ["deepfake", "injection", "mask", "print", "screen"]
            },
        }
        report.update(overrides)
        return (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")

    def verify(self, report_bytes, *, expected_model_hash=None, signature=None):
        actual_signature = self.private_key.sign(report_bytes) if signature is None else signature
        return verify_calibration_report(
            report_bytes,
            hashlib.sha256(report_bytes).hexdigest(),
            expected_model_hash or self.model_hash,
            self.public_b64,
            base64.b64encode(actual_signature).decode("ascii"),
        )

    def test_valid_signed_v3_report_is_accepted(self):
        self.assertTrue(self.verify(self.report_bytes()))

    def test_tampered_report_is_rejected(self):
        original = self.report_bytes()
        signature = self.private_key.sign(original)
        tampered = self.report_bytes(approved=False)
        self.assertFalse(self.verify(tampered, signature=signature))

    def test_wrong_model_or_failed_gate_is_rejected(self):
        report = self.report_bytes()
        self.assertFalse(self.verify(report, expected_model_hash="c" * 64))
        self.assertFalse(self.verify(self.report_bytes(diversityGatePassed=False)))

    def test_legacy_or_incomplete_attack_report_is_rejected(self):
        self.assertFalse(self.verify(self.report_bytes(schema="ostrovua-biometric-evaluation-v1")))
        self.assertFalse(self.verify(self.report_bytes(missingAttacks=["mask"])))
        self.assertFalse(self.verify(self.report_bytes(transactionMetrics=None)))


if __name__ == "__main__":
    unittest.main()
