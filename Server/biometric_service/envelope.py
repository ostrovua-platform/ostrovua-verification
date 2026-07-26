"""X25519 + HKDF-SHA256 + AES-256-GCM evidence envelope.

Only a one-request biometric worker loads the private key or sees plaintext.
The long-lived auth process forwards an opaque, App-Attest-bound envelope.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CONTRACT = "self-hosted-envelope-v3"
CONTEXT = b"ostrovua-biometric-envelope-v3"
MAGIC = b"OUVE3"
ENVELOPE_VERSIONS = {
    CONTRACT: (CONTEXT, MAGIC, True, True),
}
MAX_DG1_BYTES = 128 * 1024
MAX_DG2_BYTES = 2 * 1024 * 1024
MAX_FACE_BYTES = 1024 * 1024
MAX_DG14_BYTES = 128 * 1024
MAX_DG15_BYTES = 128 * 1024
MAX_AA_SIGNATURE_BYTES = 1024
MAX_FRAME_BYTES = 256 * 1024
MAX_DEPTH_BYTES = 2 + 16 * 16 * 2
MAX_CHALLENGE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_PLAINTEXT_BYTES = MAX_TOTAL_BYTES + 1024


class EnvelopeError(ValueError):
    pass


def _exact_keys(value: Any, expected: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == expected


def _decode(value: Any, expected: int | None, maximum: int, field: str) -> bytearray:
    if not isinstance(value, str) or not value or len(value) > ((maximum + 2) // 3) * 4:
        raise EnvelopeError(f"{field}_invalid")
    try:
        decoded = bytearray(base64.b64decode(value, validate=True))
    except (ValueError, TypeError) as error:
        raise EnvelopeError(f"{field}_invalid") from error
    if (expected is not None and len(decoded) != expected) or len(decoded) > maximum or \
       base64.b64encode(decoded).decode("ascii") != value:
        decoded[:] = b"\x00" * len(decoded)
        raise EnvelopeError(f"{field}_invalid")
    return decoded


class _Reader:
    def __init__(self, data: bytearray):
        self.data = data
        self.offset = 0
        self.content_bytes = 0

    def take(self, count: int, field: str) -> bytearray:
        if count < 0 or self.offset + count > len(self.data):
            raise EnvelopeError(f"{field}_truncated")
        value = bytearray(self.data[self.offset:self.offset + count])
        self.offset += count
        return value

    def uint8(self, field: str) -> int:
        return self.take(1, field)[0]

    def uint32(self, field: str) -> int:
        raw = self.take(4, field)
        try:
            return struct.unpack(">I", raw)[0]
        finally:
            raw[:] = b"\x00" * len(raw)

    def blob(self, maximum: int, field: str) -> bytearray:
        length = self.uint32(f"{field}_length")
        if length == 0 or length > maximum:
            raise EnvelopeError(f"{field}_size_invalid")
        self.content_bytes += length
        if self.content_bytes > MAX_TOTAL_BYTES:
            raise EnvelopeError("evidence_oversized")
        return self.take(length, field)

    def optional_blob(self, maximum: int, field: str) -> bytearray | None:
        length = self.uint32(f"{field}_length")
        if length == 0:
            return None
        if length > maximum:
            raise EnvelopeError(f"{field}_size_invalid")
        self.content_bytes += length
        if self.content_bytes > MAX_TOTAL_BYTES:
            raise EnvelopeError("evidence_oversized")
        return self.take(length, field)


def parse_plaintext(plaintext: bytearray, contract: str = CONTRACT) -> dict[str, Any]:
    version = ENVELOPE_VERSIONS.get(contract)
    if version is None:
        raise EnvelopeError("envelope_version_invalid")
    _, magic, has_depth, has_document_auth = version
    reader = _Reader(plaintext)
    if reader.take(len(magic), "magic") != magic:
        raise EnvelopeError("envelope_magic_invalid")
    owned: list[bytearray] = []
    try:
        dg1 = reader.blob(MAX_DG1_BYTES, "dg1")
        dg2 = reader.blob(MAX_DG2_BYTES, "dg2")
        face = reader.blob(MAX_FACE_BYTES, "dg2_face")
        owned.extend((dg1, dg2, face))
        if dg2.find(face) < 0:
            raise EnvelopeError("dg2_face_not_bound_to_dg2")

        dg14 = None
        dg15 = None
        ca_passed = False
        aa_passed = False
        aa_challenge = None
        aa_signature = None
        if has_document_auth:
            dg14 = reader.optional_blob(MAX_DG14_BYTES, "dg14")
            dg15 = reader.optional_blob(MAX_DG15_BYTES, "dg15")
            ca_code = reader.uint8("chip_authentication")
            aa_code = reader.uint8("active_authentication")
            if ca_code not in (0, 1) or aa_code not in (0, 1):
                raise EnvelopeError("document_authentication_state_invalid")
            ca_passed = ca_code == 1
            aa_passed = aa_code == 1
            aa_challenge = reader.optional_blob(8, "aa_challenge")
            aa_signature = reader.optional_blob(
                MAX_AA_SIGNATURE_BYTES, "aa_signature")
            for value in (dg14, dg15, aa_challenge, aa_signature):
                if value is not None:
                    owned.append(value)
            if ca_passed and dg14 is None:
                raise EnvelopeError("chip_authentication_evidence_missing")
            if aa_passed != all(
                value is not None
                for value in (dg15, aa_challenge, aa_signature)
            ):
                raise EnvelopeError("active_authentication_evidence_missing")

        neutral_count = reader.uint8("neutral_count")
        if not 3 <= neutral_count <= 5:
            raise EnvelopeError("neutral_count_invalid")
        neutral = []
        for index in range(neutral_count):
            frame = reader.blob(MAX_FRAME_BYTES, f"neutral_{index}")
            owned.append(frame)
            neutral.append(frame)

        challenge_count = reader.uint8("challenge_count")
        if not 12 <= challenge_count <= 24:
            raise EnvelopeError("challenge_count_invalid")
        challenge = []
        challenge_bytes = 0
        previous_offset = -1
        for index in range(challenge_count):
            offset_ms = reader.uint32(f"challenge_{index}_offset")
            if offset_ms <= previous_offset or offset_ms > 30_000:
                raise EnvelopeError(f"challenge_{index}_timeline_invalid")
            previous_offset = offset_ms
            frame = reader.blob(MAX_FRAME_BYTES, f"challenge_{index}")
            challenge_bytes += len(frame)
            if challenge_bytes > MAX_CHALLENGE_BYTES:
                raise EnvelopeError("challenge_bytes_oversized")
            owned.append(frame)
            depth = None
            if has_depth:
                depth = reader.blob(MAX_DEPTH_BYTES, f"challenge_{index}_depth")
                if len(depth) != MAX_DEPTH_BYTES or depth[0] != 16 or depth[1] != 16:
                    raise EnvelopeError(f"challenge_{index}_depth_invalid")
                owned.append(depth)
            challenge.append({"offsetMs": offset_ms, "jpeg": frame, "depth": depth})
        if reader.offset != len(plaintext):
            raise EnvelopeError("envelope_trailing_bytes")
        return {
            "dg1": dg1,
            "dg2": dg2,
            "dg2Face": face,
            "dg14": dg14,
            "dg15": dg15,
            "chipAuthenticationPassed": ca_passed,
            "activeAuthenticationPassed": aa_passed,
            "activeAuthenticationChallenge": aa_challenge,
            "activeAuthenticationSignature": aa_signature,
            "neutralFrames": neutral,
            "challengeFrames": challenge,
            "envelopeVersion": contract,
        }
    except Exception:
        for value in owned:
            value[:] = b"\x00" * len(value)
        raise


class EnvelopeDecryptor:
    def __init__(
        self,
        private_key: X25519PrivateKey,
        secondary_private_key: X25519PrivateKey | None = None,
    ):
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = hashlib.sha256(public_bytes).hexdigest()
        self._private_keys = {self.key_id: private_key}
        if secondary_private_key is not None:
            secondary_public = secondary_private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            secondary_key_id = hashlib.sha256(secondary_public).hexdigest()
            if secondary_key_id == self.key_id:
                raise RuntimeError("biometric envelope secondary key duplicates active key")
            self._private_keys[secondary_key_id] = secondary_private_key
            self.secondary_key_id = secondary_key_id
        else:
            self.secondary_key_id = None
        self.accepted_key_ids = tuple(sorted(self._private_keys))

    @staticmethod
    def _load_private_key(path: Path, label: str) -> X25519PrivateKey:
        raw = bytearray(path.read_bytes())
        try:
            if len(raw) != 32:
                raise RuntimeError(f"{label} must be 32 raw bytes")
            return X25519PrivateKey.from_private_bytes(bytes(raw))
        finally:
            raw[:] = b"\x00" * len(raw)

    @classmethod
    def from_environment(cls) -> "EnvelopeDecryptor":
        path = Path(os.environ.get(
            "BIOMETRIC_ENVELOPE_PRIVATE_KEY_FILE", "/run/secrets/envelope_private.key"))
        active = cls._load_private_key(path, "biometric envelope private key")
        secondary_path = os.environ.get(
            "BIOMETRIC_ENVELOPE_SECONDARY_PRIVATE_KEY_FILE", "")
        secondary = cls._load_private_key(
            Path(secondary_path), "biometric envelope secondary private key"
        ) if secondary_path else None
        decryptor = cls(active, secondary)
        expected_key_id = os.environ.get(
            "BIOMETRIC_ENVELOPE_ACTIVE_KEY_SHA256", "")
        expected_secondary_key_id = os.environ.get(
            "BIOMETRIC_ENVELOPE_SECONDARY_KEY_SHA256", "")
        production = os.environ.get("APP_ENV") == "production"
        if (production and (
            len(expected_key_id) != 64 or
            any(character not in "0123456789abcdef" for character in expected_key_id)
        )):
            raise RuntimeError("biometric envelope active key pin is required")
        if expected_key_id and expected_key_id != decryptor.key_id:
            raise RuntimeError("biometric envelope active key pin mismatch")
        if secondary is not None:
            if production and (
                len(expected_secondary_key_id) != 64 or
                any(
                    character not in "0123456789abcdef"
                    for character in expected_secondary_key_id
                )
            ):
                raise RuntimeError("biometric envelope secondary key pin is required")
            if expected_secondary_key_id != decryptor.secondary_key_id:
                raise RuntimeError("biometric envelope secondary key pin mismatch")
        elif expected_secondary_key_id:
            raise RuntimeError("biometric envelope secondary key pin has no key file")
        return decryptor

    def decrypt(self, envelope: Any, challenge_b64: Any) -> dict[str, Any]:
        expected = {"contract", "keyId", "ephemeralPublicKey", "nonce", "ciphertext"}
        contract = envelope.get("contract") if isinstance(envelope, dict) else None
        version = ENVELOPE_VERSIONS.get(contract)
        key_id = envelope.get("keyId") if isinstance(envelope, dict) else None
        if not isinstance(key_id, str) or len(key_id) != 64 or \
           any(character not in "0123456789abcdef" for character in key_id):
            raise EnvelopeError("envelope_shape_invalid")
        private_key = self._private_keys.get(key_id)
        if not _exact_keys(envelope, expected) or version is None or private_key is None:
            raise EnvelopeError("envelope_shape_invalid")
        context, _, _, _ = version
        challenge = _decode(challenge_b64, 32, 32, "challenge")
        ephemeral = _decode(envelope.get("ephemeralPublicKey"), 32, 32, "ephemeral_key")
        nonce = _decode(envelope.get("nonce"), 12, 12, "nonce")
        ciphertext = _decode(
            envelope.get("ciphertext"), None, MAX_PLAINTEXT_BYTES + 16, "ciphertext")
        plaintext = bytearray()
        try:
            try:
                shared = private_key.exchange(
                    X25519PublicKey.from_public_bytes(bytes(ephemeral)))
                key = HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=bytes(challenge), info=context
                ).derive(shared)
                aad = context + b"\n" + key_id.encode("ascii") + b"\n" + bytes(challenge)
                plaintext = bytearray(AESGCM(key).decrypt(bytes(nonce), bytes(ciphertext), aad))
            except (InvalidTag, ValueError) as error:
                raise EnvelopeError("envelope_authentication_failed") from error
            if len(plaintext) > MAX_PLAINTEXT_BYTES:
                raise EnvelopeError("plaintext_oversized")
            return parse_plaintext(plaintext, contract)
        finally:
            challenge[:] = b"\x00" * len(challenge)
            ephemeral[:] = b"\x00" * len(ephemeral)
            nonce[:] = b"\x00" * len(nonce)
            ciphertext[:] = b"\x00" * len(ciphertext)
            plaintext[:] = b"\x00" * len(plaintext)


def wipe_evidence(evidence: Any) -> None:
    if not isinstance(evidence, dict):
        return
    values = [
        evidence.get("dg1"), evidence.get("dg2"), evidence.get("dg2Face"),
        evidence.get("dg14"), evidence.get("dg15"),
        evidence.get("activeAuthenticationChallenge"),
        evidence.get("activeAuthenticationSignature"),
    ]
    values.extend(evidence.get("neutralFrames") or [])
    values.extend(entry.get("jpeg") for entry in (evidence.get("challengeFrames") or [])
                  if isinstance(entry, dict))
    values.extend(entry.get("depth") for entry in (evidence.get("challengeFrames") or [])
                  if isinstance(entry, dict))
    for value in values:
        if isinstance(value, bytearray):
            value[:] = b"\x00" * len(value)
