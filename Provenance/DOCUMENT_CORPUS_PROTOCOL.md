# Real AA/CA/passive document corpus

This protocol prepares evidence for an independent eMRTD cryptography review.
It is not a substitute for that review and does not activate Verified ID.

## Privacy boundary

The aggregate corpus never contains:

- DG1 or DG2 bytes;
- name, document number, date of birth or expiry;
- document portrait, selfie or embedding;
- AA signature or raw APDU transcript;
- account, email, App Attest key or production request identifier.

The input uses a newly generated pseudonymous `caseId`, opaque
`documentSeries`, coarse device/OS classes, cryptographic profile labels,
expected/observed outcomes and SHA-256 digests. A separately retained evidence
fixture may be provided to the independent auditor only with consent, access
control, encryption and an approved deletion date.

Do not derive `caseId` from MRZ, DG1, DG2, an account ID or a document number.

## Required profiles

- `aa_rsa`
- `aa_ecdsa`
- `ca`
- `passive_only`
- `negative`

The default engineering gate requires five independent evidence digests and
two document series per profile across at least two issuing states. The
independent reviewer must approve the final coverage matrix before collection.

`passive_only` must expect `pending_review`. `negative` must expect `reject`.
Every row must be bound to one reviewed server artifact hash. Duplicate case
IDs and duplicate evidence digests are rejected.

## JSONL row

```json
{
  "schema": "ostrovua-document-corpus-v1",
  "caseId": "random-case-0001",
  "profile": "aa_rsa",
  "issuingState": "UKR",
  "documentSeries": "opaque-series-a",
  "deviceClass": "iphone-true-depth-a",
  "osClass": "ios-supported-a",
  "expectedOutcome": "auto_eligible",
  "observedOutcome": "auto_eligible",
  "passiveAuthentication": "passed",
  "activeAuthentication": "rsa",
  "chipAuthentication": "not_supported",
  "dg14Profile": "none",
  "dg15Profile": "rsa-iso9796",
  "serverArtifactSha256": "64-lowercase-hex",
  "evidenceSha256": "64-lowercase-hex"
}
```

Unknown fields are rejected so personal data cannot accidentally be appended.

## Evaluation

```sh
python Server/tools/evaluate_document_corpus.py \
  /secure/document-corpus.jsonl \
  --expected-server-sha256 <reviewed-server-artifact-sha256> \
  --output /secure/document-corpus-report.json \
  --require-pass
```

The output contains only aggregate counts, coverage gates and the source file
SHA-256. A passing local report means the planned corpus is internally
complete; it does not mean the cryptography implementation has passed an
independent audit.

## Frozen release evidence

After all reviewed code is committed, the tree is clean and both container
images have immutable digests:

```sh
python Server/tools/build_release_evidence_manifest.py \
  --repo "$PWD" \
  --image auth=sha256:<auth-image-digest> \
  --image biometric=sha256:<biometric-image-digest> \
  --output /secure/ostrovua-release-evidence.json
```

The production manifest must have `git.clean=true`. `--allow-dirty` is for
local rehearsal only and cannot support a GO decision.
