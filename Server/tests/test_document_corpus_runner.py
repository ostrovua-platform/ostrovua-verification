import hashlib
import sys
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from evaluate_document_corpus import evaluate  # noqa: E402


class DocumentCorpusRunnerTests(unittest.TestCase):
    server_hash = "a" * 64

    @classmethod
    def row(cls, profile, index, state="UKR", series="series-a", **overrides):
        values = {
            "schema": "ostrovua-document-corpus-v1",
            "caseId": f"{profile}-{state}-{series}-{index}",
            "profile": profile,
            "issuingState": state,
            "documentSeries": series,
            "deviceClass": "iphone-true-depth-a",
            "osClass": "ios-supported-a",
            "expectedOutcome": "auto_eligible",
            "observedOutcome": "auto_eligible",
            "passiveAuthentication": "passed",
            "activeAuthentication": "not_supported",
            "chipAuthentication": "not_supported",
            "dg14Profile": "none",
            "dg15Profile": "none",
            "serverArtifactSha256": cls.server_hash,
            "evidenceSha256": hashlib.sha256(
                f"{profile}:{state}:{series}:{index}".encode("ascii")
            ).hexdigest(),
        }
        if profile == "aa_rsa":
            values.update(activeAuthentication="rsa", dg15Profile="rsa-iso9796")
        elif profile == "aa_ecdsa":
            values.update(activeAuthentication="ecdsa", dg15Profile="ecdsa-p256")
        elif profile == "ca":
            values.update(chipAuthentication="passed", dg14Profile="ecdh-aes128")
        elif profile == "passive_only":
            values.update(
                expectedOutcome="pending_review",
                observedOutcome="pending_review",
            )
        elif profile == "negative":
            values.update(
                expectedOutcome="reject",
                observedOutcome="reject",
                passiveAuthentication="failed",
                activeAuthentication="failed",
                chipAuthentication="failed",
                dg14Profile="invalid",
                dg15Profile="invalid",
            )
        values.update(overrides)
        return values

    @classmethod
    def complete_rows(cls):
        rows = []
        for profile in ("aa_rsa", "aa_ecdsa", "ca", "passive_only", "negative"):
            for index in range(5):
                state = "UKR" if index < 3 else "DEU"
                series = "series-a" if index % 2 == 0 else "series-b"
                rows.append(cls.row(profile, index, state=state, series=series))
        return rows

    def test_complete_pseudonymous_corpus_passes(self):
        report = evaluate(
            self.complete_rows(),
            expected_server_sha256=self.server_hash,
        )
        self.assertTrue(report["approved"])
        self.assertEqual(report["counts"]["total"], 25)
        self.assertFalse(report["privacy"]["containsRawDocumentData"])

    def test_outcome_mismatch_fails_closed(self):
        rows = self.complete_rows()
        rows[0]["observedOutcome"] = "reject"
        report = evaluate(rows)
        self.assertFalse(report["outcomeGatePassed"])
        self.assertFalse(report["approved"])

    def test_multiple_server_builds_fail_artifact_gate(self):
        rows = self.complete_rows()
        rows[0]["serverArtifactSha256"] = "b" * 64
        self.assertFalse(evaluate(rows)["artifactGatePassed"])

    def test_personal_data_field_is_rejected(self):
        rows = self.complete_rows()
        rows[0]["documentNumber"] = "not-allowed"
        with self.assertRaisesRegex(ValueError, "shape_invalid"):
            evaluate(rows)

    def test_profile_inconsistency_is_rejected(self):
        rows = self.complete_rows()
        rows[0]["activeAuthentication"] = "not_supported"
        with self.assertRaisesRegex(ValueError, "aa_rsa_profile_inconsistent"):
            evaluate(rows)


if __name__ == "__main__":
    unittest.main()
