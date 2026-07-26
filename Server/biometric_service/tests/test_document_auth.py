import hashlib
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE))

from document_auth import (  # noqa: E402
    DocumentAuthenticationError,
    derive_aa_challenge,
    dg14_supports_chip_authentication,
    verify_active_authentication,
)


def length(value):
    if value < 128:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag, value):
    return bytes([tag]) + length(len(value)) + value


def oid(value):
    parts = [int(part) for part in value.split(".")]
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        values = [part & 0x7F]
        part >>= 7
        while part:
            values.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(reversed(values))
    return tlv(0x06, encoded)


def dg14_for_aa(signature_oid="0.4.0.127.0.7.1.1.4.1.3"):
    info = tlv(
        0x30,
        oid("2.23.136.1.1.5") + tlv(0x02, b"\x01") + oid(signature_oid),
    )
    return tlv(0x6E, tlv(0x31, info))


def dg14_for_ca():
    public_info = tlv(
        0x30,
        oid("0.4.0.127.0.7.2.2.1.2") +
        tlv(0x30, oid("1.2.840.10045.2.1") + oid("1.2.840.10045.3.1.7")) +
        tlv(0x03, b"\x00\x04" + b"\x01" * 64),
    )
    return tlv(0x6E, tlv(0x31, public_info))


def dg15(public_key):
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return tlv(0x6F, spki)


class DocumentAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(32))
        self.challenge = derive_aa_challenge(self.seed)

    def test_ecdsa_active_authentication_is_verified_server_side(self):
        key = ec.generate_private_key(ec.SECP256R1())
        der_signature = key.sign(self.challenge, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        plain_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        result = verify_active_authentication(
            dg14_for_aa(), dg15(key.public_key()), self.seed,
            self.challenge, plain_signature,
        )
        self.assertEqual(result, {"status": "passed", "method": "ecdsa-sha256"})

        tampered = bytearray(plain_signature)
        tampered[-1] ^= 1
        with self.assertRaisesRegex(DocumentAuthenticationError, "signature_invalid"):
            verify_active_authentication(
                dg14_for_aa(), dg15(key.public_key()), self.seed,
                self.challenge, tampered,
            )

    def test_challenge_is_bound_to_the_server_nonce(self):
        key = ec.generate_private_key(ec.SECP256R1())
        der_signature = key.sign(self.challenge, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_signature)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        with self.assertRaisesRegex(DocumentAuthenticationError, "challenge_mismatch"):
            verify_active_authentication(
                dg14_for_aa(), dg15(key.public_key()), bytes(reversed(self.seed)),
                self.challenge, signature,
            )

    def test_iso9796_rsa_active_authentication_is_verified(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        numbers = key.private_numbers()
        key_bytes = key.key_size // 8
        message = bytes(range(key_bytes - 1 - 32 - 2))
        digest = hashlib.sha256(message + self.challenge).digest()
        recovered = b"\x6a" + message + digest + b"\x34\xcc"
        signature = pow(
            int.from_bytes(recovered, "big"), numbers.d, numbers.public_numbers.n
        ).to_bytes(key_bytes, "big")

        result = verify_active_authentication(
            None, dg15(key.public_key()), self.seed, self.challenge, signature,
        )
        self.assertEqual(result, {"status": "passed", "method": "rsa-sha256"})

    def test_dg14_ca_capability_is_not_a_client_boolean(self):
        self.assertTrue(dg14_supports_chip_authentication(dg14_for_ca()))
        self.assertFalse(dg14_supports_chip_authentication(dg14_for_aa()))


if __name__ == "__main__":
    unittest.main()
