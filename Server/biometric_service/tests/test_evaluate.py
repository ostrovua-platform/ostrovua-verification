import sys
import unittest
from pathlib import Path


SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE))

from evaluate import evaluate, wilson  # noqa: E402


class EvaluationTests(unittest.TestCase):
    @staticmethod
    def transaction(category, trial, subject, **overrides):
        values = {
            "category": category,
            "trial": trial,
            "subject": subject,
            "neutralFaceScores": [0.70] * 3,
            "challengeFaceScores": [0.70] * 12,
            "padScores": [1.0] * 12,
            "qualityPassed": True,
            "depthPassed": True,
            "challengePassed": True,
        }
        values.update(overrides)
        return values

    @staticmethod
    def complete_rows():
        subjects = [f"p{i:02d}" for i in range(20)]
        rows = [
            EvaluationTests.transaction(
                "genuine_face", f"genuine-{i:03d}", subjects[i % 10])
            for i in range(30)
        ]
        pairs = []
        for left in range(20):
            for right in range(left + 1, 20):
                pairs.append((subjects[left], subjects[right]))
        rows += [
            EvaluationTests.transaction(
                "impostor_face",
                f"impostor-{index:03d}",
                left,
                comparisonSubject=right,
                neutralFaceScores=[0.10] * 3,
                challengeFaceScores=[0.10] * 12,
            )
            for index, (left, right) in enumerate(pairs[:100])
        ]
        rows += [
            EvaluationTests.transaction(
                "bona_fide_pad", f"bona-fide-{i:03d}", subjects[i % 10])
            for i in range(30)
        ]
        for attack in ("print", "screen", "mask", "injection", "deepfake"):
            rows += [
                EvaluationTests.transaction(
                    "attack_pad",
                    f"{attack}-{i:03d}",
                    subjects[i % 5],
                    attack=attack,
                    padScores=[0.10] * 12,
                    depthPassed=False,
                    challengePassed=False,
                )
                for i in range(35)
            ]
        return rows

    def test_zero_of_35_has_about_ten_percent_upper_bound(self):
        low, high = wilson(0, 35)
        self.assertEqual(low, 0.0)
        self.assertLess(high, 0.10)
        self.assertGreater(high, 0.09)

    def test_complete_holdout_can_pass(self):
        report = evaluate(self.complete_rows())
        self.assertTrue(report["approved"])
        self.assertTrue(report["diversityGatePassed"])
        self.assertEqual(report["missingAttacks"], [])

    def test_one_screen_attack_blocks_apcer_gate(self):
        rows = self.complete_rows()
        screen = next(row for row in rows
                      if row["category"] == "attack_pad" and row["attack"] == "screen")
        screen["padScores"] = [1.0] * 12
        screen["depthPassed"] = True
        screen["challengePassed"] = True
        report = evaluate(rows)
        self.assertFalse(report["accuracyGatePassed"])

    def test_missing_attack_class_blocks_sample_gate(self):
        rows = [row for row in self.complete_rows()
                if row.get("attack") != "deepfake"]
        report = evaluate(rows)
        self.assertFalse(report["sampleGatePassed"])
        self.assertEqual(report["missingAttacks"], ["deepfake"])

    def test_repeated_single_subject_blocks_diversity_gate(self):
        rows = self.complete_rows()
        for row in rows:
            if row["category"] != "impostor_face":
                row["subject"] = "one-person"
        report = evaluate(rows)
        self.assertFalse(report["diversityGatePassed"])
        self.assertFalse(report["approved"])

    def test_unknown_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "shape_invalid"):
            row = self.transaction("genuine_face", "genuine-001", "p01")
            row["person"] = "secret"
            evaluate([row])

    def test_legacy_single_score_rows_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "shape_invalid"):
            evaluate([{
                "category": "genuine_face",
                "subject": "p01",
                "score": 0.70,
            }])

    def test_face_metrics_apply_production_minimum_and_median_policy(self):
        rows = self.complete_rows()
        rows[0]["challengeFaceScores"] = [0.70] * 11 + [0.20]
        report = evaluate(rows)
        self.assertEqual(report["metrics"]["fnmr"]["errors"], 1)
        self.assertEqual(
            report["transactionMetrics"]["genuineFalseReject"]["errors"], 1)

    def test_pad_metrics_apply_depth_and_challenge_policy(self):
        rows = self.complete_rows()
        bona_fide = next(row for row in rows if row["category"] == "bona_fide_pad")
        bona_fide["depthPassed"] = False
        report = evaluate(rows)
        self.assertEqual(report["metrics"]["bpcer"]["errors"], 1)
        self.assertEqual(
            report["transactionMetrics"]["bonaFideFalseReject"]["errors"], 1)

    def test_duplicate_trial_is_rejected(self):
        rows = self.complete_rows()
        rows[1]["trial"] = rows[0]["trial"]
        with self.assertRaisesRegex(ValueError, "trial_invalid"):
            evaluate(rows)


if __name__ == "__main__":
    unittest.main()
