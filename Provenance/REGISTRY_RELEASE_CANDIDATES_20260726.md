# Private registry release candidates — 2026-07-26

## Outcome

The auth and biometric `linux/amd64` release candidates were built from the
clean source commit
`d804b0a27a30fc034a33cc47599d105c69a852ed`, published to the private
project registry, pulled again by immutable digest, and smoke-tested from those
digest-qualified references.

No production host was contacted, no production compose file was changed, no
container was recreated, and no verification, shadow, or calibration flag was
enabled.

## Controlled registry

- repository: `docker.io/whoami33/ostrovua-release-candidates`
- visibility: private, confirmed through the authenticated Docker Hub API
- unauthenticated repository metadata: HTTP 404
- target platform: `linux/amd64`

The Docker Hub plan permits one private repository. Both service candidates
therefore use separate tags inside the same private repository. Deployment must
use only the complete digest-qualified references below; tags are labels, not
deployment authority.

## Frozen image references

### Auth

- audit tag: `auth-v7-d804b0a2-amd64`
- deploy reference:
  `docker.io/whoami33/ostrovua-release-candidates@sha256:4eaa5256cbb76c3cb3bb7358d61cfca091395e53b84330f6fea8504c9c257b63`
- OCI index digest:
  `sha256:4eaa5256cbb76c3cb3bb7358d61cfca091395e53b84330f6fea8504c9c257b63`
- `linux/amd64` manifest:
  `sha256:5f8d2f53013f7abfdf7ceb6ab3ebc9906472dc0515cbdb1d8f06ff89e61e95fa`
- attestation manifest:
  `sha256:9c02e1689138ccc3d1e9b704e7c4d0df6a109aaa1bc72580f8d86d5e0e34bdd0`
- runtime user: `12000:12000`
- size: 52,913,162 bytes

The image contains a fixed numeric user and group. Application code and
dependencies remained non-writable, while `/app/uploads` and the private
`/tmp` test mount were writable. All runtime JavaScript parsed under Node.js
`v20.20.2`. The digest-pulled image passed with no network, a read-only root
filesystem, all Linux capabilities dropped, `no-new-privileges`, and a
64-process limit.

The dark-compose builder now forces `user: 12000:12000`; the canonical compose
gate rejects any other auth runtime user. This prevents a legacy compose file
from overriding the image back to root.

### Biometric

- audit tag: `biometric-v7-d804b0a2-amd64`
- deploy reference:
  `docker.io/whoami33/ostrovua-release-candidates@sha256:3f90e6e169c285c1ab6cd02d1ed4abb83bac9c5bfad7dcdbf3aab536f390c041`
- OCI index digest:
  `sha256:3f90e6e169c285c1ab6cd02d1ed4abb83bac9c5bfad7dcdbf3aab536f390c041`
- `linux/amd64` manifest:
  `sha256:38e2638beb0d62b08b5822a508645cebd3e9adccb1e6461db71585881d55cd61`
- attestation manifest:
  `sha256:f33bd37bf26bd7b747aab947b8c15f8290819cce5adef6eb3c3f112b93c277df`
- runtime user: `12001:12001`
- size: 552,678,719 bytes
- model-set hash:
  `291e044feb6c53e2ac9903094bcffd8a20519ef0ee1391c51c0c956ea771c0d0`
- calibration approved: false

The digest-pulled biometric image passed both pinned-model smoke tests under a
read-only root filesystem, no network, all capabilities dropped,
`no-new-privileges`, private non-executable tmpfs mounts, a 64-process limit,
and a 2 GiB memory limit. The observed fixture scores remained:

- live: `0.999879`
- print spoof: `0.228581`
- screen spoof: `0.002344`

These fixtures prove image integrity and basic separation only. They do not
replace independent APCER/BPCER/FMR/FNMR calibration.

## Verification and provenance

- Node tests: 66 passed, 0 failed
- biometric model smoke: 2 passed, 0 failed, 0 skipped
- pull by immutable digest: passed for both images
- OCI source revision label: exact source commit on both images
- clean-tree release evidence:
  `Provenance/RELEASE_EVIDENCE_V7_D804B0A2.json`
- machine-readable registry map:
  `Provenance/REGISTRY_RELEASE_CANDIDATES_V7.json`

The earlier `5b1c23c1` intermediate tags were removed after the final
compose-level non-root guard was committed. They are not release candidates.

## Production boundary

These artifacts are release candidates, not production approval. Before an
auth rollout, the existing production uploads volume must be backed up and its
root directory ownership verified or migrated to `12000:12000`; otherwise the
new process will correctly refuse to write to a root-owned legacy volume.

The global release decision remains **NO-GO** until the outstanding real
AA/CA/passive document corpus, independent cryptographic review, independent
biometric measurements, and signed calibration report are completed.
