# OstrovUA self-hosted biometric worker

The service performs face matching, presentation-attack detection,
server-side verification of the nonce-derived liveness challenge and
ICAO document anti-cloning evidence. It has no database, object storage,
analytics SDK or public route.

Privacy boundary:

- clients encrypt a challenge-bound binary evidence envelope using X25519,
  HKDF-SHA256 and AES-256-GCM; the long-lived auth service has only the public
  key and forwards ciphertext without decoding biometric evidence;
- the envelope private key is mounted read-only only into this service;
- models and request bodies exist only inside a one-request Gunicorn worker;
- the master does not preload native models; `max_requests=1` destroys the
  worker address space after every response;
- decoded byte arrays and image matrices are overwritten before return;
- production runs with a read-only filesystem, `tmpfs`, no core dumps, no
  capabilities and no swap;
- access logs are disabled and responses contain only decision metrics;
- the HMAC-authenticated service is reachable only from the internal auth
  network;
- every authenticated request carries a 128-bit nonce consumed atomically by
  a process-shared filesystem replay cache. Replay, cache corruption,
  capacity exhaustion or cache unavailability fails closed.

Envelope-key trust and rotation:

- auth publishes only the raw public key whose SHA-256 equals
  `BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256`;
- the biometric worker independently requires
  `BIOMETRIC_ENVELOPE_ACTIVE_KEY_SHA256` to match its active private key;
- an optional `BIOMETRIC_ENVELOPE_SECONDARY_PRIVATE_KEY_FILE` is accepted only
  with its own exact `BIOMETRIC_ENVELOPE_SECONDARY_KEY_SHA256` pin;
- decryption selects a key strictly by the envelope `keyId`; there is no
  trial-decryption fallback;
- zero-downtime rotation deploys the new private key as secondary, changes the
  auth public key and pin only after worker health reports both accepted key
  IDs, promotes the new key to active after the maximum challenge lifetime,
  then removes the old secondary key after another full lifetime.

Document authentication:

- raw DG14/DG15 and the AA transcript exist only inside envelope v3;
- their hashes must be verified against SOD by the auth service;
- DG15 requires AA over a fresh server-derived challenge. This worker parses
  the DG15 public key and independently verifies RSA/ECDSA AA signatures;
- DG14 CA is performed through the constrained server-owned relay outside the
  biometric envelope: auth selects the protocol, owns the ephemeral private
  key and independently verifies one protected GET CHALLENGE response;
- the resulting one-time receipt is bound to the App Attest key, document
  challenge and the worker-computed DG14 SHA-256, then consumed atomically
  with Verified ID activation;
- client-reported `chipAuthentication=passed` remains
  `chip_authentication_attested` and review-only. Only the database-backed
  `chip_authentication_server` receipt or server-verified AA can authorize
  automatic activation;
- server-owned CA proves chip possession for the fresh transcript but cannot
  eliminate a sophisticated controlled live relay by itself. Relay-resistance
  remains a measured release-gate risk.

`BIOMETRIC_CALIBRATION_APPROVED=1` and a mounted read-only aggregate report
are required for a `passed` decision. `BIOMETRIC_CALIBRATION_ID` must be the
64-character SHA-256 of the exact report bytes, while
`BIOMETRIC_CALIBRATION_MODEL_SET_HASH` and
`BIOMETRIC_CALIBRATION_POLICY_VERSION` must exactly match the running worker.
The exact report must also verify under the independent Ed25519 public key and
signature supplied in `BIOMETRIC_CALIBRATION_PUBLIC_KEY` and
`BIOMETRIC_CALIBRATION_SIGNATURE`. Without every matching element, the service
returns `calibration_not_approved` (fail-closed).

An authenticated request may carry `evaluationOnly: true` only through the
auth service's separately enabled, contributor-allowlisted shadow lane. The
worker then computes a provisional decision before final calibration approval
and signs the `self-hosted-result-v2` response with `evaluationOnly: true`.
Only this lane contains `calibrationSignals`: bounded per-frame face/PAD scores
and the three final gate booleans needed to reproduce `policy.decide`. It never
contains images, embeddings, DG contents, motion landmarks or depth geometry.
Normal production responses must carry `calibrationSignals: null`. The auth
route must stop before document-token derivation or any database mutation.
Derived score series are still biometric evaluation data: they must be
pseudonymized, transferred to the independent evaluator under the approved
test protocol and deleted under its retention schedule. This lane is for
physical TestFlight measurements, not production Verified ID issuance and not
a substitute for the signed adversarial holdout.

Models are pinned by SHA-256 in `model_manifest.json`. SFace is Apache-2.0,
YuNet is MIT, MediaPipe is Apache-2.0, and MiniFASNet is Apache-2.0. The two
MiniFASNet ONNX files are deterministic exports of upstream commit
`b6d5f04ad78778917853b25c778acef6d5626d15`.

MiniFASNet preprocessing must remain raw OpenCV BGR float32 in the `0...255`
range. Upstream's `ToTensor` deliberately does not divide by 255. A parity
test and the live/spoof smoke fixtures guard this security-critical contract.

Run the complete reproducible smoke suite from the backend directory:

```sh
sh biometric_service/fetch_smoke_fixtures.sh /tmp/ostrovua-biometric-fixtures
BIOMETRIC_MODEL_DIR="$PWD/biometric_service/models" \
BIOMETRIC_MODEL_MANIFEST="$PWD/biometric_service/model_manifest.json" \
SILENT_FACE_FIXTURE_DIR=/tmp/ostrovua-biometric-fixtures \
python -m unittest discover -s biometric_service/tests -v
```

The three Apache-2.0 upstream fixtures are fetched from commit
`b6d5f04ad78778917853b25c778acef6d5626d15` and accepted only when their
individual SHA-256 digests match.

Production calibration is generated with `evaluate.py` from an independent
JSONL holdout. Version 3 accepts only complete transaction score series:
neutral and challenge face scores, PAD scores, quality, TrueDepth and active
challenge results. FMR/FNMR and per-attack APCER/BPCER are derived through the
same `policy.decide` function used by the production worker; the report also
contains end-to-end transaction error rates with 95% Wilson intervals.
Legacy single-score rows are rejected. The output contains only aggregates
and a source digest. Rows use unique trial aliases and non-identifying
participant aliases solely to enforce cohort diversity; neither appears in
the aggregate report.

Approval requires every attack class (`print`, `screen`, `mask`, `injection`,
`deepfake`), at least 35 trials and 5 target participants per class, 30 genuine
face and 30 bona-fide PAD trials across at least 10 participants, and 100
impostor comparisons covering at least 50 distinct pairs. Changing a report,
model, preprocessing, policy, signature or public key invalidates approval.

Generate a release evidence manifest only after the reviewed tree is clean:

```sh
python Server/tools/build_release_evidence_manifest.py \
  --repo "$PWD" \
  --image auth=sha256:<reviewed-auth-image-digest> \
  --image biometric=sha256:<reviewed-biometric-image-digest> \
  --output /secure/ostrovua-release-evidence.json
```

The command deliberately refuses a dirty tree and refuses to write its output
inside the repository.
