"""Pure, deterministic decision policy for self-hosted biometric verification."""

from __future__ import annotations

from dataclasses import dataclass
from statistics import median
from typing import Iterable, Sequence


POLICY_VERSION = "ostrovua-self-hosted-2026-07-v2"
FACE_NEUTRAL_MEDIAN_MIN = 0.50
FACE_NEUTRAL_SINGLE_MIN = 0.40
FACE_CHALLENGE_MEDIAN_MIN = 0.45
FACE_CHALLENGE_SINGLE_MIN = 0.32
PAD_MEDIAN_MIN = 0.80
PAD_SINGLE_MIN = 0.50
PAD_PASS_FRACTION_MIN = 0.75
YAW_NEUTRAL_MAX = 0.08
YAW_ACTION_MIN = 0.12
BLINK_OPEN_MAX = 0.35
BLINK_CLOSED_MIN = 0.60
DEPTH_COVERAGE_MIN = 0.55
DEPTH_BASELINE_REQUIRED = 4
DEPTH_RELIEF_SIDE_MIN_METERS = 0.002
DEPTH_RELIEF_MEDIAN_MIN_METERS = 0.008
DEPTH_RELIEF_MAX_METERS = 0.080


def policy_parameters() -> dict[str, object]:
    """Return the exact, report-safe parameters enforced by ``decide``.

    Calibration reports embed this object and the production verifier compares
    it byte-for-byte with the running policy.  Keeping the values here avoids a
    second, potentially drifting copy in the evaluator.
    """
    return {
        "face": {
            "neutralMedianMinimum": FACE_NEUTRAL_MEDIAN_MIN,
            "neutralSingleMinimum": FACE_NEUTRAL_SINGLE_MIN,
            "challengeMedianMinimum": FACE_CHALLENGE_MEDIAN_MIN,
            "challengeSingleMinimum": FACE_CHALLENGE_SINGLE_MIN,
        },
        "pad": {
            "medianMinimum": PAD_MEDIAN_MIN,
            "singleMinimum": PAD_SINGLE_MIN,
            "passScoreMinimum": 0.70,
            "passFractionMinimum": PAD_PASS_FRACTION_MIN,
        },
        "depth": {
            "coverageMinimum": DEPTH_COVERAGE_MIN,
            "baselineRequired": DEPTH_BASELINE_REQUIRED,
            "reliefSideMinimumMeters": DEPTH_RELIEF_SIDE_MIN_METERS,
            "reliefMedianMinimumMeters": DEPTH_RELIEF_MEDIAN_MIN_METERS,
            "reliefMaximumMeters": DEPTH_RELIEF_MAX_METERS,
        },
        "evidence": {
            "neutralFramesMinimum": 3,
            "neutralFramesMaximum": 5,
            "challengeFramesMinimum": 12,
            "challengeFramesMaximum": 24,
            "qualityPassFractionMinimum": 0.75,
        },
    }


@dataclass(frozen=True)
class MotionSignal:
    offset_ms: int
    yaw: float
    blink: float


@dataclass(frozen=True)
class DepthSignal:
    valid_fraction: float
    center_depth_meters: float
    left_relief_meters: float
    right_relief_meters: float

    @property
    def mean_relief_meters(self) -> float:
        return (self.left_relief_meters + self.right_relief_meters) / 2.0


def _finite_unit(values: Iterable[float]) -> bool:
    return all(isinstance(value, (int, float)) and -1.0 <= float(value) <= 1.0
               for value in values)


def quality_gate(neutral_quality: Sequence[bool],
                 challenge_quality: Sequence[bool]) -> bool:
    """Reject generally poor evidence without failing on one transient blur.

    Face detection, face/PAD minimums and the active challenge remain strict.
    This gate only stops a single low-quality neutral frame from rejecting an
    otherwise strong multi-frame genuine run.
    """
    if len(neutral_quality) < 3 or len(challenge_quality) < 12 or \
       any(not isinstance(value, bool) for value in (*neutral_quality, *challenge_quality)):
        return False
    neutral_good = sum(neutral_quality)
    challenge_good = sum(challenge_quality)
    return neutral_good >= 3 and neutral_good / len(neutral_quality) >= 0.75 and \
        challenge_good / len(challenge_quality) >= 0.75


def depth_gate(signals: Sequence[DepthSignal | None]) -> tuple[bool, str, float, float]:
    """Require synchronized 3D facial relief; never fall back to RGB-only.

    The first six challenge samples are the immutable neutral baseline created
    by the client sampler. A flat or tilted display cannot put the nose in
    front of *both* cheeks, while the bilateral check tolerates global plane
    tilt and rejects a screen viewed at an angle.
    """
    if len(signals) < 12 or len(signals) > 24 or any(signal is None for signal in signals):
        return False, "depth_evidence_required", 0.0, 0.0
    typed = [signal for signal in signals if signal is not None]
    if any(not all(map(lambda value: isinstance(value, (int, float)), (
        signal.valid_fraction,
        signal.center_depth_meters,
        signal.left_relief_meters,
        signal.right_relief_meters,
    ))) for signal in typed):
        return False, "depth_evidence_invalid", 0.0, 0.0

    structurally_valid = [
        signal for signal in typed
        if DEPTH_COVERAGE_MIN <= signal.valid_fraction <= 1.0
        and 0.15 <= signal.center_depth_meters <= 1.50
        and -0.10 <= signal.left_relief_meters <= 0.10
        and -0.10 <= signal.right_relief_meters <= 0.10
    ]
    valid_fraction = len(structurally_valid) / len(typed)
    baseline = [
        signal for signal in typed[:6]
        if signal in structurally_valid
        and signal.left_relief_meters >= DEPTH_RELIEF_SIDE_MIN_METERS
        and signal.right_relief_meters >= DEPTH_RELIEF_SIDE_MIN_METERS
        and signal.mean_relief_meters <= DEPTH_RELIEF_MAX_METERS
    ]
    reliefs = [signal.mean_relief_meters for signal in baseline]
    relief_median = float(median(reliefs)) if reliefs else 0.0
    if valid_fraction < 0.75:
        return False, "depth_quality_failed", relief_median, valid_fraction
    if len(baseline) < DEPTH_BASELINE_REQUIRED or \
       relief_median < DEPTH_RELIEF_MEDIAN_MIN_METERS:
        return False, "depth_geometry_failed", relief_median, valid_fraction
    return True, "passed", relief_median, valid_fraction


def verify_challenge(signals: Sequence[MotionSignal], expected: Sequence[str]) -> tuple[bool, str]:
    if len(signals) < 12 or len(signals) > 24 or len(expected) != 2:
        return False, "challenge_shape_invalid"
    if any(action not in {"turnLeft", "turnRight", "blink"} for action in expected):
        return False, "challenge_action_invalid"
    offsets = [signal.offset_ms for signal in signals]
    if offsets[0] < 0 or offsets[-1] > 30_000 or any(b <= a for a, b in zip(offsets, offsets[1:])):
        return False, "challenge_timeline_invalid"
    if not _finite_unit(signal.yaw for signal in signals) or \
       not all(0.0 <= signal.blink <= 1.0 for signal in signals):
        return False, "challenge_signal_invalid"

    baseline_candidates = [signal.yaw for signal in signals[:6] if signal.blink <= 0.50]
    if len(baseline_candidates) < 3:
        return False, "challenge_baseline_missing"
    baseline = median(baseline_candidates)
    deviations = [signal.yaw - baseline for signal in signals]

    cursor = 0
    for action in expected:
        neutral_run = 0
        armed_index = None
        for index in range(cursor, len(signals)):
            neutral = abs(deviations[index]) <= YAW_NEUTRAL_MAX and \
                signals[index].blink <= 0.50
            neutral_run = neutral_run + 1 if neutral else 0
            if neutral_run >= 2:
                armed_index = index
                break
        if armed_index is None:
            return False, "challenge_neutral_missing"

        event_index = None
        for index in range(armed_index + 1, len(signals)):
            deviation = deviations[index]
            blink = signals[index].blink
            if action == "turnLeft":
                if deviation >= YAW_ACTION_MIN:
                    return False, "challenge_wrong_action"
                if deviation <= -YAW_ACTION_MIN:
                    event_index = index
                    break
            elif action == "turnRight":
                if deviation <= -YAW_ACTION_MIN:
                    return False, "challenge_wrong_action"
                if deviation >= YAW_ACTION_MIN:
                    event_index = index
                    break
            else:
                had_open = any(s.blink <= BLINK_OPEN_MAX for s in signals[armed_index:index])
                if had_open and blink >= BLINK_CLOSED_MIN:
                    event_index = index
                    break

        if event_index is None:
            # The signed worker response contract permits lowercase
            # snake_case reasons only. Keep client action identifiers
            # camelCase, but never leak that spelling into the contract.
            reason_action = {
                "turnLeft": "turn_left",
                "turnRight": "turn_right",
                "blink": "blink",
            }[action]
            return False, f"challenge_{reason_action}_missing"
        cursor = event_index + 1

    return True, "passed"


def decide(*, neutral_face_scores: Sequence[float], challenge_face_scores: Sequence[float],
           pad_scores: Sequence[float], challenge_passed: bool,
           quality_passed: bool, depth_passed: bool,
           calibration_approved: bool) -> tuple[str, str]:
    if not calibration_approved:
        return "unavailable", "calibration_not_approved"
    if not quality_passed:
        return "failed", "image_quality_failed"
    if len(neutral_face_scores) < 3 or len(challenge_face_scores) < 3 or len(pad_scores) < 12:
        return "failed", "insufficient_samples"
    if not _finite_unit(neutral_face_scores) or not _finite_unit(challenge_face_scores) or \
       not all(0.0 <= value <= 1.0 for value in pad_scores):
        return "failed", "score_range_invalid"
    if median(neutral_face_scores) < FACE_NEUTRAL_MEDIAN_MIN or \
       min(neutral_face_scores) < FACE_NEUTRAL_SINGLE_MIN:
        return "failed", "face_mismatch"
    if median(challenge_face_scores) < FACE_CHALLENGE_MEDIAN_MIN or \
       min(challenge_face_scores) < FACE_CHALLENGE_SINGLE_MIN:
        return "failed", "identity_continuity_failed"
    if not depth_passed:
        return "failed", "depth_geometry_failed"
    if median(pad_scores) < PAD_MEDIAN_MIN or min(pad_scores) < PAD_SINGLE_MIN:
        return "failed", "passive_pad_failed"
    pad_fraction = sum(score >= 0.70 for score in pad_scores) / len(pad_scores)
    if pad_fraction < PAD_PASS_FRACTION_MIN:
        return "failed", "passive_pad_unstable"
    if not challenge_passed:
        return "failed", "active_challenge_failed"
    return "passed", "passed"
