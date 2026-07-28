"""Authenticated internal API. Every Gunicorn worker serves one request then exits."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

from flask import Flask, Response, request

from engine import BiometricEngine, EvidenceError
from envelope import EnvelopeDecryptor, EnvelopeError, wipe_evidence
from replay_cache import NonceReplayCache


MAX_BODY_BYTES = 12 * 1024 * 1024
AUTH_WINDOW_SECONDS = 30


def _load_secret() -> bytes:
    secret_path = os.environ.get("BIOMETRIC_HMAC_SECRET_FILE", "")
    if secret_path:
        try:
            secret = open(secret_path, "rb").read()
        except OSError as error:
            raise RuntimeError("BIOMETRIC_HMAC_SECRET_FILE is unavailable") from error
        if len(secret) != 32:
            raise RuntimeError("BIOMETRIC_HMAC_SECRET_FILE must contain exactly 32 random bytes")
        return secret
    if os.environ.get("APP_ENV") == "production":
        raise RuntimeError("BIOMETRIC_HMAC_SECRET_FILE is required in production")
    value = os.environ.get("BIOMETRIC_HMAC_SECRET", "")
    try:
        secret = base64.b64decode(value, validate=True)
    except Exception as error:
        raise RuntimeError("BIOMETRIC_HMAC_SECRET must be canonical base64") from error
    if len(secret) != 32:
        raise RuntimeError("BIOMETRIC_HMAC_SECRET must contain exactly 32 random bytes")
    return secret


SECRET = _load_secret()
ENGINE = BiometricEngine.from_environment()
ENVELOPE = EnvelopeDecryptor.from_environment()
REPLAY_CACHE = NonceReplayCache()
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES


def _json_response(payload: dict, status: int = 200, request_id: str = "-") -> Response:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    message = f"v1\n{request_id}\n{timestamp}\n{digest}".encode("ascii")
    signature = hmac.new(SECRET, message, hashlib.sha256).hexdigest()
    response = Response(body, status=status, content_type="application/json")
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Biometric-Timestamp"] = timestamp
    response.headers["X-Biometric-Signature"] = signature
    return response


def _authenticate(body: bytes) -> bool:
    timestamp = request.headers.get("X-Biometric-Timestamp", "")
    nonce = request.headers.get("X-Biometric-Nonce", "")
    signature = request.headers.get("X-Biometric-Signature", "")
    if not timestamp.isdigit() or len(nonce) != 32 or not all(c in "0123456789abcdef" for c in nonce) or \
       len(signature) != 64 or not all(c in "0123456789abcdef" for c in signature):
        return False
    if abs(int(time.time()) - int(timestamp)) > AUTH_WINDOW_SECONDS:
        return False
    digest = hashlib.sha256(body).hexdigest()
    message = f"v1\n{timestamp}\n{nonce}\n{digest}".encode("ascii")
    expected = hmac.new(SECRET, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected) and REPLAY_CACHE.consume(nonce)


def _decode_challenge(value: object, field: str) -> bytearray:
    if not isinstance(value, str) or len(value) != 44:
        raise EvidenceError(f"{field}_invalid")
    try:
        decoded = bytearray(base64.b64decode(value, validate=True))
    except (TypeError, ValueError) as error:
        raise EvidenceError(f"{field}_invalid") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        decoded[:] = b"\x00" * len(decoded)
        raise EvidenceError(f"{field}_invalid")
    return decoded


@app.get("/healthz")
def health() -> Response:
    payload = ENGINE.health()
    payload["envelopeKeyId"] = ENVELOPE.key_id
    payload["acceptedEnvelopeKeyIds"] = list(ENVELOPE.accepted_key_ids)
    return _json_response(payload)


@app.post("/v1/verify")
def verify() -> Response:
    raw_body = request.get_data(cache=False, as_text=False)
    request_id = "-"
    evidence = None
    document_challenge = None
    try:
        if not _authenticate(raw_body):
            return _json_response({"error": "unauthorized"}, 401)
        payload = json.loads(raw_body)
        if isinstance(payload, dict) and isinstance(payload.get("requestId"), str):
            request_id = payload["requestId"]
        if not isinstance(payload, dict) or set(payload) != {
            "contract", "requestId", "expectedActions", "challenge", "envelope",
            "documentChallenge", "evaluationOnly"
        } or payload.get("contract") != "self-hosted-forward-v2":
            raise EvidenceError("payload_shape_invalid")
        document_challenge = _decode_challenge(
            payload.get("documentChallenge"), "document_challenge")
        evidence = ENVELOPE.decrypt(payload.get("envelope"), payload.get("challenge"))
        result = ENGINE.verify(
            request_id, payload.get("expectedActions"), evidence,
            document_challenge,
            payload.get("evaluationOnly"))
        return _json_response(result, 200, request_id)
    except (EvidenceError, EnvelopeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return _json_response({"error": str(error)}, 400, request_id)
    except Exception:
        # Never log an exception object: image decoders can include source data.
        return _json_response({"error": "internal_verification_failure"}, 503, request_id)
    finally:
        wipe_evidence(evidence)
        if isinstance(document_challenge, bytearray):
            document_challenge[:] = b"\x00" * len(document_challenge)
        # bytes are immutable; the max_requests=1 worker exits after response,
        # which destroys its entire address space. Do not reuse this worker.
        raw_body = b""
