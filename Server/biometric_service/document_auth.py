"""Server-side ICAO Active Authentication verification.

DG14/DG15 and the AA transcript arrive only inside the authenticated
one-request envelope. The caller must still verify their hashes against SOD.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


AA_INFO_OID = "2.23.136.1.1.5"
CA_PUBLIC_KEY_OIDS = {
    "0.4.0.127.0.7.2.2.1.1",
    "0.4.0.127.0.7.2.2.1.2",
}
ECDSA_HASH_OIDS = {
    "0.4.0.127.0.7.1.1.4.1.1": hashes.SHA1,
    "0.4.0.127.0.7.1.1.4.1.2": hashes.SHA224,
    "0.4.0.127.0.7.1.1.4.1.3": hashes.SHA256,
    "0.4.0.127.0.7.1.1.4.1.4": hashes.SHA384,
    "0.4.0.127.0.7.1.1.4.1.5": hashes.SHA512,
}
RSA_TRAILERS = {
    0xBC: ("sha1", 20),
    0x33: ("sha1", 20),
    0x34: ("sha256", 32),
    0x35: ("sha512", 64),
    0x36: ("sha384", 48),
    0x38: ("sha224", 28),
}


class DocumentAuthenticationError(ValueError):
    pass


@dataclass(frozen=True)
class _TLV:
    tag: int
    content_start: int
    end: int


def _tlv(data: bytes | bytearray, offset: int) -> _TLV:
    if offset < 0 or offset >= len(data):
        raise DocumentAuthenticationError("document_auth_tlv_truncated")
    first = data[offset]
    cursor = offset + 1
    tag = first
    if first & 0x1F == 0x1F:
        tag = 0
        while True:
            if cursor >= len(data):
                raise DocumentAuthenticationError("document_auth_tag_truncated")
            value = data[cursor]
            cursor += 1
            tag = (tag << 8) | value
            if value & 0x80 == 0:
                break
    if cursor >= len(data):
        raise DocumentAuthenticationError("document_auth_length_truncated")
    first_length = data[cursor]
    cursor += 1
    if first_length & 0x80:
        count = first_length & 0x7F
        if count == 0 or count > 4 or cursor + count > len(data):
            raise DocumentAuthenticationError("document_auth_length_invalid")
        length = 0
        for value in data[cursor:cursor + count]:
            length = (length << 8) | value
        cursor += count
    else:
        length = first_length
    end = cursor + length
    if end > len(data):
        raise DocumentAuthenticationError("document_auth_value_truncated")
    return _TLV(tag=tag, content_start=cursor, end=end)


def _children(data: bytes | bytearray, parent: _TLV) -> list[_TLV]:
    result = []
    cursor = parent.content_start
    while cursor < parent.end:
        child = _tlv(data, cursor)
        if child.end > parent.end:
            raise DocumentAuthenticationError("document_auth_child_invalid")
        result.append(child)
        cursor = child.end
    if cursor != parent.end:
        raise DocumentAuthenticationError("document_auth_children_invalid")
    return result


def _oid(data: bytes | bytearray, value: _TLV) -> str:
    if value.tag != 0x06 or value.content_start >= value.end:
        raise DocumentAuthenticationError("document_auth_oid_invalid")
    raw = data[value.content_start:value.end]
    first = raw[0]
    parts = [min(first // 40, 2), first - min(first // 40, 2) * 40]
    current = 0
    for byte in raw[1:]:
        current = (current << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            parts.append(current)
            current = 0
    if raw[-1] & 0x80:
        raise DocumentAuthenticationError("document_auth_oid_invalid")
    return ".".join(str(part) for part in parts)


def _strip_application_group(raw: bytes | bytearray, expected_tag: int) -> bytes:
    outer = _tlv(raw, 0)
    if outer.tag != expected_tag or outer.end != len(raw):
        raise DocumentAuthenticationError("document_auth_data_group_invalid")
    return bytes(raw[outer.content_start:outer.end])


def _active_auth_hash(raw_dg14: bytes | bytearray | None):
    if raw_dg14 is None:
        raise DocumentAuthenticationError("aa_algorithm_missing")
    content = _strip_application_group(raw_dg14, 0x6E)
    root = _tlv(content, 0)
    if root.end != len(content) or root.tag not in (0x30, 0x31):
        raise DocumentAuthenticationError("dg14_security_infos_invalid")
    for info in _children(content, root):
        if info.tag != 0x30:
            continue
        values = _children(content, info)
        if len(values) >= 3 and _oid(content, values[0]) == AA_INFO_OID:
            algorithm_oid = _oid(content, values[2])
            factory = ECDSA_HASH_OIDS.get(algorithm_oid)
            if factory is None:
                raise DocumentAuthenticationError("aa_algorithm_unsupported")
            return factory()
    raise DocumentAuthenticationError("aa_algorithm_missing")


def dg14_supports_chip_authentication(
    raw_dg14: bytes | bytearray | None,
) -> bool:
    if raw_dg14 is None:
        return False
    content = _strip_application_group(raw_dg14, 0x6E)
    root = _tlv(content, 0)
    if root.end != len(content) or root.tag not in (0x30, 0x31):
        raise DocumentAuthenticationError("dg14_security_infos_invalid")
    for info in _children(content, root):
        if info.tag != 0x30:
            continue
        values = _children(content, info)
        if values and _oid(content, values[0]) in CA_PUBLIC_KEY_OIDS:
            return True
    return False


def derive_aa_challenge(challenge_seed: bytes | bytearray) -> bytes:
    if len(challenge_seed) != 32:
        raise DocumentAuthenticationError("document_challenge_invalid")
    return hashlib.sha256(
        b"ostrovua-aa-v1\x00" + bytes(challenge_seed)
    ).digest()[:8]


def _verify_rsa(
    key: rsa.RSAPublicKey,
    challenge: bytes,
    signature: bytes | bytearray,
) -> str:
    numbers = key.public_numbers()
    key_bytes = (key.key_size + 7) // 8
    if len(signature) == 0 or len(signature) > key_bytes:
        raise DocumentAuthenticationError("aa_signature_invalid")
    recovered = bytearray(
        pow(int.from_bytes(signature, "big"), numbers.e, numbers.n)
        .to_bytes(key_bytes, "big")
    )
    try:
        if len(recovered) < 24 or recovered[0] != 0x6A:
            raise DocumentAuthenticationError("aa_rsa_encoding_invalid")
        trailer = recovered.pop()
        if trailer == 0xCC:
            if not recovered:
                raise DocumentAuthenticationError("aa_rsa_trailer_invalid")
            trailer = recovered.pop()
        algorithm = RSA_TRAILERS.get(trailer)
        if algorithm is None:
            raise DocumentAuthenticationError("aa_algorithm_unsupported")
        name, digest_length = algorithm
        if len(recovered) <= digest_length + 1:
            raise DocumentAuthenticationError("aa_rsa_encoding_invalid")
        message = recovered[1:-digest_length]
        embedded = bytes(recovered[-digest_length:])
        calculated = hashlib.new(name, bytes(message) + challenge).digest()
        if not hmac.compare_digest(embedded, calculated):
            raise DocumentAuthenticationError("aa_signature_invalid")
        return f"rsa-{name}"
    finally:
        recovered[:] = b"\x00" * len(recovered)


def verify_active_authentication(
    raw_dg14: bytes | bytearray | None,
    raw_dg15: bytes | bytearray,
    challenge_seed: bytes | bytearray,
    challenge: bytes | bytearray,
    signature: bytes | bytearray,
) -> dict[str, str]:
    expected = derive_aa_challenge(challenge_seed)
    if len(challenge) != 8 or not hmac.compare_digest(bytes(challenge), expected):
        raise DocumentAuthenticationError("aa_challenge_mismatch")
    spki = _strip_application_group(raw_dg15, 0x6F)
    try:
        public_key = serialization.load_der_public_key(spki)
    except (TypeError, ValueError) as error:
        raise DocumentAuthenticationError("dg15_public_key_invalid") from error

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        digest = _active_auth_hash(raw_dg14)
        if len(signature) == 0 or len(signature) % 2 != 0:
            raise DocumentAuthenticationError("aa_signature_invalid")
        half = len(signature) // 2
        der_signature = encode_dss_signature(
            int.from_bytes(signature[:half], "big"),
            int.from_bytes(signature[half:], "big"),
        )
        try:
            public_key.verify(der_signature, expected, ec.ECDSA(digest))
        except InvalidSignature as error:
            raise DocumentAuthenticationError("aa_signature_invalid") from error
        return {"status": "passed", "method": f"ecdsa-{digest.name}"}

    if isinstance(public_key, rsa.RSAPublicKey):
        return {
            "status": "passed",
            "method": _verify_rsa(public_key, expected, signature),
        }
    raise DocumentAuthenticationError("aa_public_key_unsupported")
