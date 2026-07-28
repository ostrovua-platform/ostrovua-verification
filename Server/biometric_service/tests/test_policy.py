import sys
import unittest
from pathlib import Path


SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE))

from policy import (  # noqa: E402
    DepthSignal,
    MotionSignal,
    decide,
    depth_gate,
    quality_gate,
    verify_challenge,
)


def signals(first="turnLeft", second="blink"):
    values = [(0.0, 0.05)] * 6
    values.append((-0.25 if first == "turnLeft" else 0.25, 0.80 if first == "blink" else 0.05))
    values.extend([(0.0, 0.05), (0.0, 0.05)])
    values.append((-0.25 if second == "turnLeft" else 0.25, 0.80 if second == "blink" else 0.05))
    values.extend([(0.0, 0.05), (0.0, 0.05)])
    return [MotionSignal(index * 180, yaw, blink) for index, (yaw, blink) in enumerate(values)]


class ChallengePolicyTests(unittest.TestCase):
    def test_accepts_nonce_ordered_turn_then_blink(self):
        self.assertEqual(verify_challenge(signals(), ["turnLeft", "blink"]), (True, "passed"))

    def test_rejects_wrong_order(self):
        passed, reason = verify_challenge(signals(), ["turnRight", "blink"])
        self.assertFalse(passed)
        self.assertEqual(reason, "challenge_wrong_action")

    def test_rejects_non_monotonic_timeline(self):
        sample = signals()
        sample[7] = MotionSignal(sample[6].offset_ms, 0.0, 0.05)
        self.assertEqual(verify_challenge(sample, ["turnLeft", "blink"])[0], False)

    def test_missing_turn_reasons_follow_signed_response_contract(self):
        neutral = [MotionSignal(index * 180, 0.0, 0.05) for index in range(12)]
        self.assertEqual(
            verify_challenge(neutral, ["turnLeft", "blink"]),
            (False, "challenge_turn_left_missing"),
        )
        self.assertEqual(
            verify_challenge(neutral, ["turnRight", "blink"]),
            (False, "challenge_turn_right_missing"),
        )


class DecisionPolicyTests(unittest.TestCase):
    def valid(self, **overrides):
        values = dict(
            neutral_face_scores=[0.63, 0.60, 0.66],
            challenge_face_scores=[0.58] * 12,
            pad_scores=[0.92] * 12,
            challenge_passed=True,
            quality_passed=True,
            depth_passed=True,
            calibration_approved=True,
        )
        values.update(overrides)
        return decide(**values)

    def test_passes_complete_evidence(self):
        self.assertEqual(self.valid(), ("passed", "passed"))

    def test_calibration_gate_is_fail_closed(self):
        self.assertEqual(
            self.valid(calibration_approved=False),
            ("unavailable", "calibration_not_approved"),
        )

    def test_rejects_one_weak_identity_frame(self):
        self.assertEqual(
            self.valid(challenge_face_scores=[0.58] * 11 + [0.20]),
            ("failed", "identity_continuity_failed"),
        )

    def test_rejects_replay_like_low_pad_series(self):
        self.assertEqual(
            self.valid(pad_scores=[0.92] * 11 + [0.30]),
            ("failed", "passive_pad_failed"),
        )

    def test_rejects_missing_true_depth_even_when_rgb_pad_is_perfect(self):
        self.assertEqual(
            self.valid(depth_passed=False, pad_scores=[1.0] * 12),
            ("failed", "depth_geometry_failed"),
        )


class DepthPolicyTests(unittest.TestCase):
    @staticmethod
    def signal(relief=0.020, coverage=1.0):
        return DepthSignal(
            valid_fraction=coverage,
            center_depth_meters=0.50,
            left_relief_meters=relief,
            right_relief_meters=relief,
        )

    def test_accepts_bilateral_3d_face_relief(self):
        passed, reason, relief, coverage = depth_gate([self.signal()] * 12)
        self.assertTrue(passed)
        self.assertEqual(reason, "passed")
        self.assertAlmostEqual(relief, 0.020)
        self.assertEqual(coverage, 1.0)

    def test_rejects_flat_display_despite_perfect_rgb_pad(self):
        passed, reason, _, _ = depth_gate([self.signal(relief=0.001)] * 12)
        self.assertFalse(passed)
        self.assertEqual(reason, "depth_geometry_failed")

    def test_rejects_tilted_display_that_only_fakes_one_cheek(self):
        tilted = DepthSignal(1.0, 0.50, 0.020, -0.020)
        self.assertEqual(depth_gate([tilted] * 12)[1], "depth_geometry_failed")

    def test_rejects_rgb_only_legacy_evidence(self):
        self.assertEqual(depth_gate([None] * 12)[1], "depth_evidence_required")


class QualityPolicyTests(unittest.TestCase):
    def test_tolerates_one_transient_blur_in_multi_frame_neutral_set(self):
        self.assertTrue(quality_gate(
            [True, True, False, True, True],
            [True] * 9 + [False] * 3,
        ))

    def test_requires_three_good_neutral_frames(self):
        self.assertFalse(quality_gate(
            [True, False, True, False],
            [True] * 12,
        ))

    def test_rejects_broadly_poor_challenge_timeline(self):
        self.assertFalse(quality_gate(
            [True] * 5,
            [True] * 8 + [False] * 4,
        ))


if __name__ == "__main__":
    unittest.main()
