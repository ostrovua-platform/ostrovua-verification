import base64
import hashlib
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE))

from envelope import CONTEXT, EnvelopeDecryptor, EnvelopeError, MAGIC, wipe_evidence  # noqa: E402


def blob(value):
    return struct.pack(">I", len(value)) + value


def plaintext():
    face = b"\xff\xd8chip-face\xff\xd9"
    dg2 = b"\x75\x00" + face + b"\x00"
    result = bytearray(MAGIC)
    result += blob(b"raw-dg1") + blob(dg2) + blob(face)
    result += blob(b"") + blob(b"") + bytes([0, 0])
    result += blob(b"") + blob(b"")
    result += bytes([3])
    for index in range(3):
        result += blob(b"neutral-" + bytes([index]))
    result += bytes([12])
    depth = bytes([16, 16]) + struct.pack(">256H", *([500] * 256))
    for index in range(12):
        result += struct.pack(">I", index * 180) + \
            blob(b"challenge-" + bytes([index])) + blob(depth)
    return bytes(result)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.server_private = X25519PrivateKey.generate()
        self.decryptor = EnvelopeDecryptor(self.server_private)
        self.challenge = bytes(range(32))

    def encrypt(self, raw=None, server_private=None, key_id=None):
        server_private = server_private or self.server_private
        key_id = key_id or self.decryptor.key_id
        client_private = X25519PrivateKey.generate()
        client_public = client_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        shared = client_private.exchange(server_private.public_key())
        key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=self.challenge, info=CONTEXT
        ).derive(shared)
        nonce = bytes(range(12))
        aad = CONTEXT + b"\n" + key_id.encode() + b"\n" + self.challenge
        encrypted = AESGCM(key).encrypt(nonce, raw or plaintext(), aad)
        return {
            "contract": "self-hosted-envelope-v3",
            "keyId": key_id,
            "ephemeralPublicKey": base64.b64encode(client_public).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(encrypted).decode(),
        }

    def test_round_trip_and_explicit_wipe(self):
        evidence = self.decryptor.decrypt(
            self.encrypt(), base64.b64encode(self.challenge).decode())
        self.assertEqual(evidence["dg1"], b"raw-dg1")
        self.assertEqual(len(evidence["neutralFrames"]), 3)
        self.assertEqual(len(evidence["challengeFrames"]), 12)
        self.assertEqual(evidence["envelopeVersion"], "self-hosted-envelope-v3")
        self.assertEqual(len(evidence["challengeFrames"][0]["depth"]), 514)
        references = [
            evidence["dg1"], evidence["dg2"], evidence["dg2Face"],
            *evidence["neutralFrames"],
            *(entry["jpeg"] for entry in evidence["challengeFrames"]),
            *(entry["depth"] for entry in evidence["challengeFrames"]),
        ]
        wipe_evidence(evidence)
        self.assertTrue(all(all(value == 0 for value in item) for item in references))

    def test_ciphertext_or_challenge_tampering_fails_authentication(self):
        envelope = self.encrypt()
        ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
        ciphertext[0] ^= 1
        envelope["ciphertext"] = base64.b64encode(ciphertext).decode()
        with self.assertRaisesRegex(EnvelopeError, "authentication_failed"):
            self.decryptor.decrypt(envelope, base64.b64encode(self.challenge).decode())

        with self.assertRaisesRegex(EnvelopeError, "authentication_failed"):
            self.decryptor.decrypt(
                self.encrypt(), base64.b64encode(bytes(reversed(self.challenge))).decode())

    def test_trailing_plaintext_or_wrong_key_id_is_rejected(self):
        with self.assertRaisesRegex(EnvelopeError, "trailing_bytes"):
            self.decryptor.decrypt(
                self.encrypt(plaintext() + b"x"), base64.b64encode(self.challenge).decode())
        envelope = self.encrypt()
        envelope["keyId"] = "0" * 64
        with self.assertRaisesRegex(EnvelopeError, "shape_invalid"):
            self.decryptor.decrypt(envelope, base64.b64encode(self.challenge).decode())

    def test_legacy_envelope_contract_is_not_decryptable(self):
        envelope = self.encrypt()
        envelope["contract"] = "self-hosted-envelope-v2"
        with self.assertRaisesRegex(EnvelopeError, "shape_invalid"):
            self.decryptor.decrypt(
                envelope, base64.b64encode(self.challenge).decode())

    def test_secondary_rotation_key_is_explicitly_trusted_without_fallback(self):
        active = X25519PrivateKey.generate()
        secondary = X25519PrivateKey.generate()
        keyring = EnvelopeDecryptor(active, secondary)
        secondary_public = secondary.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        secondary_key_id = hashlib.sha256(secondary_public).hexdigest()
        evidence = keyring.decrypt(
            self.encrypt(
                server_private=secondary,
                key_id=secondary_key_id,
            ),
            base64.b64encode(self.challenge).decode(),
        )
        self.assertEqual(evidence["dg1"], b"raw-dg1")
        wipe_evidence(evidence)

        untrusted = X25519PrivateKey.generate()
        untrusted_public = untrusted.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        untrusted_key_id = hashlib.sha256(untrusted_public).hexdigest()
        with self.assertRaisesRegex(EnvelopeError, "shape_invalid"):
            keyring.decrypt(
                self.encrypt(
                    server_private=untrusted,
                    key_id=untrusted_key_id,
                ),
                base64.b64encode(self.challenge).decode(),
            )

    def test_production_keyring_requires_exact_active_and_secondary_pins(self):
        active = X25519PrivateKey.generate()
        secondary = X25519PrivateKey.generate()

        def raw_private(key):
            return key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )

        def key_id(key):
            public = key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            return hashlib.sha256(public).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            active_path = Path(directory) / "active.key"
            secondary_path = Path(directory) / "secondary.key"
            active_path.write_bytes(raw_private(active))
            secondary_path.write_bytes(raw_private(secondary))
            environment = {
                "APP_ENV": "production",
                "BIOMETRIC_ENVELOPE_PRIVATE_KEY_FILE": str(active_path),
                "BIOMETRIC_ENVELOPE_SECONDARY_PRIVATE_KEY_FILE": str(secondary_path),
                "BIOMETRIC_ENVELOPE_ACTIVE_KEY_SHA256": key_id(active),
                "BIOMETRIC_ENVELOPE_SECONDARY_KEY_SHA256": key_id(secondary),
            }
            with patch.dict(os.environ, environment, clear=False):
                decryptor = EnvelopeDecryptor.from_environment()
                self.assertEqual(len(decryptor.accepted_key_ids), 2)
                os.environ["BIOMETRIC_ENVELOPE_SECONDARY_KEY_SHA256"] = "0" * 64
                with self.assertRaisesRegex(RuntimeError, "secondary key pin mismatch"):
                    EnvelopeDecryptor.from_environment()


if __name__ == "__main__":
    unittest.main()
