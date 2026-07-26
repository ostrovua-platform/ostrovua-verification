# OstrovUA Verification Backend — Independent Security Audit Handoff

Prepared: 2026-07-26
Audit source commit: `05b1600b2e7bf6aafbaf8b43983f1105ec4443ab`

This package freezes the backend source that should be reviewed. The audit must
reference the complete 40-character commit above. Later documentation-only
commits do not change the audit target.

## Repository and scope

- Repository: `ostrovua-platform/ostrovua-verification`
- Review branch: `codex/release-freeze-v7-20260726`
- Primary scope:
  - registration, passwords, OAuth, sessions, reset and account deletion;
  - uploads and browser-facing content;
  - verification challenges, expiry, replay cache and rate limiting;
  - App Attest and server-owned CA orchestration;
  - DG1/DG2/DG14/DG15, passive authentication, AA and CA validation;
  - self-hosted face match and presentation-attack detection;
  - encrypted biometric evidence, in-memory lifetime and deletion;
  - automatic Verified ID policy, release gates and audit logging;
  - Docker build definitions, network boundaries and secret handling.

The iOS application is a separate audit target. Its frozen source is
`6504f4f5c5fdaefb1618618d8dc4392ddf79fd72` in
`ostrovua-platform/OstrovuaDB_Contributions`.

## Security invariants

1. The client is never authoritative for passive authentication, AA, CA,
   liveness, face match or Verified ID activation.
2. A challenge is single-use, session-bound, App-Attest-bound and expires
   according to the production transaction policy.
3. Biometric evidence is accepted only through the internal service contract,
   is authenticated and replay-protected, and is not persisted as raw media.
4. Verification-critical rate limiting fails closed when its shared store is
   unavailable.
5. Automatic activation remains impossible unless every release gate is
   explicitly approved.

The detailed threat model is `docs/threat-model.md`; release criteria are in
`Provenance/PRODUCTION_RELEASE_GATE_V7.md`.

## Reproducibility

```bash
git clone git@github.com:ostrovua-platform/ostrovua-verification.git
cd ostrovua-verification
git checkout 05b1600b2e7bf6aafbaf8b43983f1105ec4443ab
git status --short
shasum -a 256 \
  Server/package-lock.json \
  Server/biometric_service/requirements.txt \
  Server/biometric_service/model_manifest.json \
  Server/Dockerfile \
  Server/biometric_service/Dockerfile \
  docs/threat-model.md \
  Provenance/PRODUCTION_RELEASE_GATE_V7.md \
  Server/.env.example
```

Run source-level tests:

```bash
cd Server
npm ci
npm test
cd biometric_service
python3 -m venv .venv
. .venv/bin/activate
pip install --requirement requirements.txt
python -m unittest discover -s tests -v
```

Build the two application images from the frozen source:

```bash
docker build --pull --no-cache \
  --tag ostrovua-auth:audit-05b1600b \
  --file Server/Dockerfile Server
docker build --pull --no-cache \
  --tag ostrovua-biometric:audit-05b1600b \
  --file Server/biometric_service/Dockerfile \
  Server/biometric_service
docker image inspect \
  ostrovua-auth:audit-05b1600b \
  ostrovua-biometric:audit-05b1600b \
  --format '{{.Id}} {{json .RepoDigests}}'
```

The final release candidate must be rebuilt by CI, pushed to a private registry
and deployed by immutable `name@sha256:...` references. Local image IDs are not
a substitute for registry digests.

## Configuration without secrets

`Server/.env.example` is the canonical key inventory for local development. It
contains no credential values. Copying it to `Server/.env` is allowed only for
local use; `.env` and `.env.*` are ignored by Git.

Production should supply secrets through read-only `/run/secrets` mounts and
the supported `*_FILE` variables. Environment variables are visible to Docker
administrators and should not be the preferred production secret channel.

The following release flags were observed disabled in the production runtime
snapshot:

| Flag | Auth | Biometric |
|---|---:|---:|
| `SELF_HOSTED_VERIFICATION_ENABLED` | `0` | — |
| `BIOMETRIC_CALIBRATION_APPROVED` | `0` | `0` |
| `BIOMETRIC_SHADOW_MODE_ENABLED` | `0` | — |
| `SERVER_OWNED_CA_ENABLED` | `0` | — |
| `AUTH_SESSION_ENFORCEMENT_ENABLED` | `0` | — |

All five controls must remain `0` during dark deployment. Shadow testing must
use a separate approved staging policy; it must not silently enable production
Verified ID.

## Runtime evidence boundary

`Provenance/AUDIT_MANIFEST.json` records a read-only production snapshot
observed on 2026-07-26: compose checksums, image IDs, isolation controls and
feature flags. The current local image tags had no registry `RepoDigest`.
Therefore the snapshot:

- proves what was observed at runtime;
- does **not** prove that the deployed image equals the new audit source commit;
- must not be used as the immutable release bill of materials.

After review, CI must produce new registry digests from the accepted commit,
execute model smoke tests inside those exact images, sign the evidence manifest
and deploy only those digests.

One residual configuration issue was observed: the biometric container uses
read-only secret mounts and strong isolation, while the auth runtime still has
some secrets supplied as inline environment variables. Values were not
collected. These should be migrated to supported file-backed secrets before
production approval.

## Endpoint inventory

The source-derived route list is in
`Provenance/ENDPOINT_INVENTORY.md`. The auditor should validate authentication,
authorization, CSRF/state binding, content types, body limits, replay behavior,
rate limiting, error disclosure and deletion semantics for every route.

## Test status

- Node security suite: 65/65 passed.
- Biometric Python suite: 43 passed, 2 model-dependent tests skipped.
- Known-pattern credential scan: no match in the current tree or scanned Git
  history.
- Model file hashes match the committed model manifest.
- Model smoke tests inside the **new final digest-pinned images** remain
  pending.
- Real AA/CA/passive document corpus, independent cryptographic review,
  independent APCER/BPCER/FMR/FNMR measurements and the signed calibration
  report remain pending.

The known-pattern credential scan is bounded evidence, not proof that every
possible secret is absent. The auditor should add entropy scanning and manual
review of Git history, build context, images, configuration and logs.

## Auditor deliverables

The final report should contain:

1. a declaration of no participation in development and no conflict of
   interest;
2. exact source commits, registry image digests, model hashes and configuration
   versions;
3. scope, exclusions, threat model and test methodology;
4. findings with severity, affected code, evidence and reproduction steps;
5. remediation verification against new exact commits and image digests;
6. residual risks and an explicit production recommendation;
7. auditor identity, qualifications, signature and date.

## Current release position

The current decision is **NO-GO** for automatic Verified ID. A production
approval requires, at minimum:

- immutable registry digests built from the accepted commits;
- successful model smoke inside those exact images;
- a real AA/CA/passive document corpus and independent DG14/CA/ISO 9796 review;
- independent PAD/biometric measurements and a signed calibration report;
- backup/restore, migration, race, fault and load evidence;
- dark-deploy validation with every release flag disabled;
- remediation or explicit acceptance of every high-risk residual finding.
