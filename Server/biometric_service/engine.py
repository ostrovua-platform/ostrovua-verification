"""In-memory face match, passive PAD and active challenge verification."""

from __future__ import annotations

import hashlib
import json
import os
from io import BytesIO
from pathlib import Path
from statistics import median
from typing import Any

import cv2
import mediapipe as mp
import numpy as np
import onnxruntime as ort
from PIL import Image, ImageOps, UnidentifiedImageError
from calibration import calibration_is_approved
from document_auth import (
    DocumentAuthenticationError,
    dg14_supports_chip_authentication,
    verify_active_authentication,
)
from policy import (
    POLICY_VERSION,
    DepthSignal,
    MotionSignal,
    decide,
    depth_gate,
    quality_gate,
    verify_challenge,
)


MAX_PIXELS = 12_000_000
ALLOWED_IMAGE_FORMATS = {"JPEG", "JPEG2000", "J2K", "JP2"}
DG_HASH_ALGORITHMS = ("sha1", "sha224", "sha256", "sha384", "sha512")


class EvidenceError(ValueError):
    pass


def _exact_keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _decode_image(encoded: bytearray, field: str) -> np.ndarray:
    try:
        with Image.open(BytesIO(encoded)) as probe:
            if probe.format not in ALLOWED_IMAGE_FORMATS or getattr(probe, "is_animated", False):
                raise EvidenceError(f"{field}_format_invalid")
            width, height = probe.size
            if width < 80 or height < 80 or width > 4096 or height > 4096 or width * height > MAX_PIXELS:
                raise EvidenceError(f"{field}_dimensions_invalid")
            probe.verify()
        with Image.open(BytesIO(encoded)) as image:
            image = ImageOps.exif_transpose(image).convert("RGB")
            rgb = np.asarray(image, dtype=np.uint8)
        return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
    except EvidenceError:
        raise
    except (UnidentifiedImageError, OSError, ValueError) as error:
        raise EvidenceError(f"{field}_decode_failed") from error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits, axis=1, keepdims=True)
    values = np.exp(shifted)
    return values / np.sum(values, axis=1, keepdims=True)


class BiometricEngine:
    def __init__(self, model_dir: Path, manifest_path: Path):
        self.model_dir = model_dir
        self.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(self.manifest, dict) or not self.manifest:
            raise RuntimeError("model manifest is empty")
        for name, expected in self.manifest.items():
            path = model_dir / name
            if not path.is_file() or _sha256(path) != expected:
                raise RuntimeError(f"model integrity failure: {name}")
        canonical = json.dumps(self.manifest, sort_keys=True, separators=(",", ":")).encode()
        self.model_set_hash = hashlib.sha256(canonical).hexdigest()

        self.detector = cv2.FaceDetectorYN.create(
            str(model_dir / "yunet.onnx"), "", (320, 320), 0.85, 0.30, 5000)
        self.recognizer = cv2.FaceRecognizerSF.create(str(model_dir / "sface.onnx"), "")
        session_options = ort.SessionOptions()
        session_options.intra_op_num_threads = 1
        session_options.inter_op_num_threads = 1
        session_options.enable_mem_pattern = False
        self.pad_models = [
            (2.7, ort.InferenceSession(
                str(model_dir / "minifas_v2_2_7.onnx"),
                sess_options=session_options, providers=["CPUExecutionProvider"])),
            (4.0, ort.InferenceSession(
                str(model_dir / "minifas_v1se_4_0.onnx"),
                sess_options=session_options, providers=["CPUExecutionProvider"])),
        ]

        base_options = mp.tasks.BaseOptions(model_asset_path=str(model_dir / "face_landmarker.task"))
        options = mp.tasks.vision.FaceLandmarkerOptions(
            base_options=base_options,
            running_mode=mp.tasks.vision.RunningMode.IMAGE,
            num_faces=2,
            min_face_detection_confidence=0.75,
            min_face_presence_confidence=0.75,
            min_tracking_confidence=0.75,
            output_face_blendshapes=True,
        )
        self.landmarker = mp.tasks.vision.FaceLandmarker.create_from_options(options)
        # The model/policy env values provide a human-readable deployment
        # cross-check; the signed report repeats and cryptographically binds
        # both values. Any absent/mismatched element keeps the worker closed.
        self.calibration_approved = \
            os.environ.get("BIOMETRIC_CALIBRATION_MODEL_SET_HASH") == self.model_set_hash and \
            os.environ.get("BIOMETRIC_CALIBRATION_POLICY_VERSION") == POLICY_VERSION and \
            calibration_is_approved(self.model_set_hash)

    @classmethod
    def from_environment(cls) -> "BiometricEngine":
        root = Path(__file__).resolve().parent
        return cls(
            Path(os.environ.get("BIOMETRIC_MODEL_DIR", root / "models")),
            Path(os.environ.get("BIOMETRIC_MODEL_MANIFEST", root / "model_manifest.json")),
        )

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "policyVersion": POLICY_VERSION,
            "modelSetHash": self.model_set_hash,
            "calibrationApproved": self.calibration_approved,
            "retention": "worker-process-lifetime",
        }

    @staticmethod
    def _resize_for_inference(image: np.ndarray) -> np.ndarray:
        height, width = image.shape[:2]
        maximum = max(height, width)
        if maximum <= 1280:
            return image
        scale = 1280.0 / maximum
        return cv2.resize(image, (round(width * scale), round(height * scale)),
                          interpolation=cv2.INTER_AREA)

    def _detect_one(self, image: np.ndarray, field: str) -> np.ndarray:
        image = self._resize_for_inference(image)
        height, width = image.shape[:2]
        self.detector.setInputSize((width, height))
        _unused, faces = self.detector.detect(image)
        if faces is None or len(faces) != 1:
            raise EvidenceError(f"{field}_face_count_invalid")
        face = faces[0]
        area = float(face[2] * face[3]) / float(width * height)
        if float(face[-1]) < 0.85 or area < 0.04 or area > 0.90:
            raise EvidenceError(f"{field}_face_quality_invalid")
        return image, face

    def _feature(self, image: np.ndarray, face: np.ndarray) -> np.ndarray:
        aligned = self.recognizer.alignCrop(image, face)
        return self.recognizer.feature(aligned)

    def _similarity(self, reference: np.ndarray, candidate: np.ndarray) -> float:
        return float(self.recognizer.match(reference, candidate, cv2.FaceRecognizerSF_FR_COSINE))

    @staticmethod
    def _visual_quality(image: np.ndarray) -> bool:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        mean = float(np.mean(gray))
        blur = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        return 35.0 <= mean <= 225.0 and blur >= 18.0

    @staticmethod
    def _crop_scaled(image: np.ndarray, face: np.ndarray, scale: float) -> np.ndarray:
        height, width = image.shape[:2]
        x, y, box_width, box_height = (float(value) for value in face[:4])
        scale = min((height - 1) / max(box_height, 1.0),
                    (width - 1) / max(box_width, 1.0), scale)
        new_width, new_height = box_width * scale, box_height * scale
        center_x, center_y = x + box_width / 2.0, y + box_height / 2.0
        left, top = center_x - new_width / 2.0, center_y - new_height / 2.0
        right, bottom = center_x + new_width / 2.0, center_y + new_height / 2.0
        if left < 0:
            right -= left
            left = 0
        if top < 0:
            bottom -= top
            top = 0
        if right > width - 1:
            left -= right - width + 1
            right = width - 1
        if bottom > height - 1:
            top -= bottom - height + 1
            bottom = height - 1
        crop = image[max(0, int(top)):int(bottom) + 1, max(0, int(left)):int(right) + 1]
        if crop.size == 0:
            raise EvidenceError("pad_crop_invalid")
        return cv2.resize(crop, (80, 80), interpolation=cv2.INTER_LINEAR)

    def _pad_score(self, image: np.ndarray, face: np.ndarray) -> float:
        probabilities = np.zeros((1, 3), dtype=np.float32)
        for scale, session in self.pad_models:
            crop = self._crop_scaled(image, face, scale)
            # Upstream MiniFASNet intentionally uses raw BGR 0...255 floats.
            # Its ToTensor implementation does not divide by 255; changing
            # this silently collapses real/spoof scores to the same class.
            tensor = np.transpose(crop.astype(np.float32), (2, 0, 1))[None, ...]
            logits = session.run(None, {session.get_inputs()[0].name: tensor})[0]
            probabilities += _softmax(logits)
            tensor.fill(0)
            crop.fill(0)
        return float(probabilities[0, 1] / len(self.pad_models))

    def _motion_signal(self, image: np.ndarray, offset_ms: int) -> MotionSignal:
        rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        result = self.landmarker.detect(mp.Image(image_format=mp.ImageFormat.SRGB, data=rgb))
        rgb.fill(0)
        if len(result.face_landmarks) != 1 or len(result.face_blendshapes) != 1:
            raise EvidenceError("challenge_landmark_face_count_invalid")
        landmarks = result.face_landmarks[0]
        if len(landmarks) < 455:
            raise EvidenceError("challenge_landmarks_incomplete")
        left_eye, right_eye, nose = landmarks[33], landmarks[263], landmarks[1]
        inter_eye = abs(right_eye.x - left_eye.x)
        if inter_eye < 0.04:
            raise EvidenceError("challenge_pose_invalid")
        yaw = (nose.x - (left_eye.x + right_eye.x) / 2.0) / inter_eye
        categories = {category.category_name: float(category.score)
                      for category in result.face_blendshapes[0]}
        blink = (categories.get("eyeBlinkLeft", 0.0) + categories.get("eyeBlinkRight", 0.0)) / 2.0
        return MotionSignal(offset_ms=offset_ms, yaw=max(-1.0, min(1.0, yaw)), blink=blink)

    @staticmethod
    def _depth_signal(encoded: bytearray | None) -> DepthSignal | None:
        if encoded is None:
            return None
        if not isinstance(encoded, bytearray) or len(encoded) != 514 or \
           encoded[0] != 16 or encoded[1] != 16:
            raise EvidenceError("depth_grid_invalid")
        grid = np.frombuffer(encoded, dtype=">u2", offset=2, count=256) \
            .astype(np.float64).reshape((16, 16))
        try:
            valid = (grid >= 150.0) & (grid <= 1500.0)
            valid_fraction = float(np.count_nonzero(valid)) / 256.0

            def region_median(rows: slice, columns: slice) -> float | None:
                region = grid[rows, columns]
                values = region[(region >= 150.0) & (region <= 1500.0)]
                return float(np.median(values)) / 1000.0 if values.size >= 8 else None

            nose = region_median(slice(6, 11), slice(6, 10))
            left = region_median(slice(6, 11), slice(2, 6))
            right = region_median(slice(6, 11), slice(10, 14))
            if nose is None or left is None or right is None:
                return DepthSignal(valid_fraction, 0.0, -0.1, -0.1)
            return DepthSignal(
                valid_fraction=valid_fraction,
                center_depth_meters=nose,
                left_relief_meters=left - nose,
                right_relief_meters=right - nose,
            )
        finally:
            grid.fill(0)

    def verify(self, request_id: Any, expected_actions: Any,
               evidence: Any, document_challenge: Any,
               evaluation_only: Any = False) -> dict[str, Any]:
        if not isinstance(request_id, str) or len(request_id) != 36:
            raise EvidenceError("request_id_invalid")
        if not isinstance(evaluation_only, bool):
            raise EvidenceError("evaluation_mode_invalid")
        if not isinstance(expected_actions, list) or len(expected_actions) != 2 or \
           any(action not in {"turnLeft", "turnRight", "blink"} for action in expected_actions):
            raise EvidenceError("expected_actions_invalid")
        expected_evidence_keys = {
            "dg1", "dg2", "dg2Face", "neutralFrames", "challengeFrames",
            "dg14", "dg15", "chipAuthenticationPassed",
            "activeAuthenticationPassed", "activeAuthenticationChallenge",
            "activeAuthenticationSignature", "envelopeVersion",
        }
        if not _exact_keys(evidence, expected_evidence_keys):
            raise EvidenceError("evidence_shape_invalid")
        neutral_input = evidence.get("neutralFrames")
        challenge_input = evidence.get("challengeFrames")
        if not isinstance(neutral_input, list) or not 3 <= len(neutral_input) <= 5 or \
           not isinstance(challenge_input, list) or not 12 <= len(challenge_input) <= 24:
            raise EvidenceError("frame_count_invalid")

        required_sensitive: list[bytearray] = [
            evidence.get("dg1"), evidence.get("dg2"), evidence.get("dg2Face"),
            *neutral_input,
            *(entry.get("jpeg") for entry in challenge_input if isinstance(entry, dict)),
            *(entry.get("depth") for entry in challenge_input
              if isinstance(entry, dict) and isinstance(entry.get("depth"), bytearray)),
        ]
        if any(not isinstance(value, bytearray) for value in required_sensitive):
            raise EvidenceError("evidence_buffer_invalid")
        optional_sensitive = [
            evidence.get("dg14"), evidence.get("dg15"),
            evidence.get("activeAuthenticationChallenge"),
            evidence.get("activeAuthenticationSignature"),
        ]
        if any(value is not None and not isinstance(value, bytearray)
               for value in optional_sensitive):
            raise EvidenceError("document_authentication_buffer_invalid")
        if not isinstance(document_challenge, bytearray) or \
           len(document_challenge) != 32:
            raise EvidenceError("document_challenge_invalid")
        sensitive = required_sensitive + [
            value for value in optional_sensitive if isinstance(value, bytearray)
        ] + [document_challenge]
        images: list[np.ndarray] = []
        features: list[np.ndarray] = []
        try:
            dg1_bytes = evidence["dg1"]
            dg2_raw = evidence["dg2"]
            dg2_bytes = evidence["dg2Face"]
            dg_hashes = {
                "dg1": {algorithm: hashlib.new(algorithm, dg1_bytes).hexdigest()
                        for algorithm in DG_HASH_ALGORITHMS},
                "dg2": {algorithm: hashlib.new(algorithm, dg2_raw).hexdigest()
                        for algorithm in DG_HASH_ALGORITHMS},
            }
            raw_dg14 = evidence.get("dg14")
            raw_dg15 = evidence.get("dg15")
            if raw_dg14 is not None:
                dg_hashes["dg14"] = {
                    algorithm: hashlib.new(algorithm, raw_dg14).hexdigest()
                    for algorithm in DG_HASH_ALGORITHMS
                }
            if raw_dg15 is not None:
                dg_hashes["dg15"] = {
                    algorithm: hashlib.new(algorithm, raw_dg15).hexdigest()
                    for algorithm in DG_HASH_ALGORITHMS
                }

            try:
                ca_supported = dg14_supports_chip_authentication(raw_dg14)
                ca_passed = evidence.get("chipAuthenticationPassed") is True
                aa_claimed = evidence.get("activeAuthenticationPassed") is True
                if ca_supported and not ca_passed:
                    raise EvidenceError("chip_authentication_required")
                if ca_passed and not ca_supported:
                    raise EvidenceError("chip_authentication_claim_invalid")

                aa_method = None
                if raw_dg15 is not None:
                    if not aa_claimed:
                        raise EvidenceError("active_authentication_required")
                    aa_result = verify_active_authentication(
                        raw_dg14,
                        raw_dg15,
                        document_challenge,
                        evidence.get("activeAuthenticationChallenge"),
                        evidence.get("activeAuthenticationSignature"),
                    )
                    aa_method = aa_result["method"]
                elif aa_claimed:
                    raise EvidenceError("active_authentication_claim_invalid")
            except DocumentAuthenticationError as error:
                raise EvidenceError(str(error)) from error

            if aa_method is not None:
                assurance = "active_authentication"
            elif ca_passed:
                # The upstream iOS library exposes only a CA status, not the
                # ephemeral key/secure-messaging transcript needed for an
                # independent server proof. App Attest binds this status to
                # the exact request, but it is not auto-activation assurance.
                assurance = "chip_authentication_attested"
            else:
                assurance = "passive_only"
            document_authentication = {
                "assurance": assurance,
                "activeAuthentication": "passed" if aa_method else "not_supported",
                "chipAuthentication": "passed" if ca_passed else "not_supported",
                "activeAuthenticationMethod": aa_method or "none",
            }
            dg2_image = _decode_image(dg2_bytes, "dg2_face")
            images.append(dg2_image)
            dg2_image, dg2_face = self._detect_one(dg2_image, "dg2_face")
            reference = self._feature(dg2_image, dg2_face)
            features.append(reference)

            neutral_scores: list[float] = []
            neutral_quality: list[bool] = []
            for index, raw in enumerate(neutral_input):
                image = _decode_image(raw, f"neutral_{index}")
                images.append(image)
                image, face = self._detect_one(image, f"neutral_{index}")
                feature = self._feature(image, face)
                features.append(feature)
                neutral_scores.append(self._similarity(reference, feature))
                neutral_quality.append(self._visual_quality(image))

            challenge_scores: list[float] = []
            pad_scores: list[float] = []
            signals: list[MotionSignal] = []
            depth_signals: list[DepthSignal | None] = []
            challenge_quality: list[bool] = []
            previous_offset = -1
            for index, entry in enumerate(challenge_input):
                if not _exact_keys(entry, {"offsetMs", "jpeg", "depth"}) or \
                   not isinstance(entry.get("offsetMs"), int) or \
                   entry["offsetMs"] <= previous_offset or entry["offsetMs"] > 30_000:
                    raise EvidenceError(f"challenge_{index}_timeline_invalid")
                previous_offset = entry["offsetMs"]
                raw = entry.get("jpeg")
                image = _decode_image(raw, f"challenge_{index}")
                images.append(image)
                image, face = self._detect_one(image, f"challenge_{index}")
                feature = self._feature(image, face)
                features.append(feature)
                challenge_scores.append(self._similarity(reference, feature))
                pad_scores.append(self._pad_score(image, face))
                signals.append(self._motion_signal(image, entry["offsetMs"]))
                depth_signals.append(self._depth_signal(entry.get("depth")))
                challenge_quality.append(self._visual_quality(image))

            challenge_passed, challenge_reason = verify_challenge(signals, expected_actions)
            quality_passed = quality_gate(neutral_quality, challenge_quality)
            depth_passed, depth_reason, depth_relief, depth_valid_fraction = \
                depth_gate(depth_signals)
            decision, reason = decide(
                neutral_face_scores=neutral_scores,
                challenge_face_scores=challenge_scores,
                pad_scores=pad_scores,
                challenge_passed=challenge_passed,
                quality_passed=quality_passed,
                depth_passed=depth_passed,
                # Shadow evaluation computes a provisional result for an
                # allowlisted physical test, but the signed response carries
                # evaluationOnly and auth is forbidden from activating ID.
                calibration_approved=self.calibration_approved or evaluation_only,
            )
            if not challenge_passed and reason == "active_challenge_failed":
                reason = challenge_reason
            if not depth_passed and reason == "depth_geometry_failed":
                reason = depth_reason
            calibration_signals = None
            if evaluation_only:
                # Calibration receives only derived scalar series. Raw images,
                # face embeddings and motion/depth geometry never leave the
                # isolated worker and are wiped in the finally block below.
                calibration_signals = {
                    "neutralFaceScores": [
                        round(float(value), 6) for value in neutral_scores
                    ],
                    "challengeFaceScores": [
                        round(float(value), 6) for value in challenge_scores
                    ],
                    "padScores": [
                        round(float(value), 6) for value in pad_scores
                    ],
                    "qualityPassed": quality_passed,
                    "depthPassed": depth_passed,
                    "challengePassed": challenge_passed,
                }
            return {
                "contract": "self-hosted-result-v2",
                "requestId": request_id,
                "decision": decision,
                "reason": reason,
                "policyVersion": POLICY_VERSION,
                "modelSetHash": self.model_set_hash,
                "faceMedian": round(float(median(neutral_scores)), 6),
                "faceMinimum": round(float(min(neutral_scores)), 6),
                "padMedian": round(float(median(pad_scores)), 6),
                "padMinimum": round(float(min(pad_scores)), 6),
                "depthMedianRelief": round(depth_relief, 6),
                "depthValidFraction": round(depth_valid_fraction, 6),
                "depthPassed": depth_passed,
                "challengePassed": challenge_passed,
                "dgHashes": dg_hashes,
                "documentAuthentication": document_authentication,
                "evaluationOnly": evaluation_only,
                "calibrationSignals": calibration_signals,
            }
        finally:
            for raw in sensitive:
                raw[:] = b"\x00" * len(raw)
            for image in images:
                image.fill(0)
            for feature in features:
                feature.fill(0)
