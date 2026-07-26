# Request for proposal: independent OstrovUA verification review

This document is a procurement scope, not a claim of certification. Crypto and
biometric work should preferably be awarded to separate organizations.

## Frozen target

The final engagement package will include:

- clean Git commit and release tag;
- immutable auth and biometric container image digests;
- `ostrovua-release-evidence-v1` manifest;
- iOS build identifier and supported device/OS matrix;
- model-set hash, policy version and policy parameters;
- ICAO trust snapshot identifier and hash;
- architecture, threat model and privacy/retention statement.

Any target-changing remediation requires a documented delta review and retest.

## Work package A: eMRTD cryptography

Independently assess:

- ICAO Passive Authentication and SOD/DG hash validation;
- DG15 Active Authentication, ECDSA and RSA ISO/IEC 9796-2;
- DG14 parsing and Chip Authentication under BSI TR-03110;
- server-owned challenge/key generation, secure messaging and transcript
  verification;
- App Attest, account, nonce, document challenge and DG14 binding;
- replay, cross-session, cross-account, downgrade and malformed DER/APDU
  behavior;
- privacy, logging, memory lifetime and persistence boundaries.

Methods must include source review, independent/differential vectors, malformed
input testing or fuzzing, and a controlled real-document corpus. Production
attack instructions or access are out of scope.

Required deliverables:

- signed PDF assessment;
- exact target hashes and scope;
- findings with severity and reproducible evidence references;
- remediation verification;
- final PASS, CONDITIONAL PASS or FAIL;
- signed machine-readable findings/target manifest if available.

Respond with evidence of prior ICAO Doc 9303, eMRTD, smartcard, BSI TR-03110
and ISO/IEC 9796-2 work.

## Work package B: biometric/PAD evaluation

Independently approve the test plan, control a locked holdout and evaluate the
exact production transaction pipeline. Report:

- FMR and FNMR;
- BPCER;
- APCER separately for print, screen/replay, 3D mask, controlled camera
  injection and reactive deepfake;
- end-to-end genuine/impostor/attack transaction error rates;
- 95% confidence intervals, sample counts and exclusion rules;
- device/OS/environment and approved demographic slices;
- bias/equity analysis appropriate to the recruited cohort.

All attempts must be logged without cherry-picking. Raw images, DG data and
embeddings must not enter the aggregate report. Transaction score series are
accepted only from the HMAC-authenticated worker `self-hosted-result-v2`
calibration response, are treated as derived biometric data, are pseudonymized
before evaluation and are deleted under the agreed retention schedule after
the signed aggregate report is produced.

Required deliverables:

- approved test plan;
- signed evaluation report;
- aggregate `ostrovua-biometric-evaluation-v3` JSON;
- Ed25519 signature and raw public verification key;
- exact source, model, policy, application and container hashes;
- PASS, CONDITIONAL PASS or FAIL.

Respond with laboratory accreditation scope, supported ISO/IEC 30107-3 and
ISO/IEC 19795 testing, participant/artifact recruitment plan, data-processing
locations, retention/deletion controls and subcontractors.

## Commercial response

Quote separately:

1. test-plan review;
2. evidence collection/recruitment;
3. laboratory execution;
4. report and cryptographic signing;
5. one remediation retest;
6. optional formal certification fees;
7. travel, document/artifact procurement and taxes.

State calendar duration, assumptions, cancellation/retest charges and whether
the laboratory fee excludes fees charged by a certification scheme.
