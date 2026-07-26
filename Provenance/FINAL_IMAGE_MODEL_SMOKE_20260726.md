# Final image and model smoke evidence — 2026-07-26

## Scope

This evidence covers local, clean `linux/amd64` builds of the auth and
biometric services from:

- repository: `ostrovua-platform/ostrovua-verification`
- source commit: `05b1600b2e7bf6aafbaf8b43983f1105ec4443ab`
- verification branch: `codex/release-freeze-v7-20260726`
- Docker server: `29.5.3`
- build host: Apple Silicon (`arm64`)
- target platform: `linux/amd64`

`git diff --quiet 05b1600b2e7bf6aafbaf8b43983f1105ec4443ab HEAD -- Server`
returned success before the evidence was recorded. The complete `Server/`
build context therefore matched the frozen source commit.

No production host was contacted, no production service was recreated, and no
verification or calibration flag was changed.

## Built artifacts

| Service | Local tag | Content digest | Size | Runtime user |
|---|---|---|---:|---|
| Auth | `ostrovua-auth:audit-05b1600b-amd64` | `sha256:0c8f987530158281d5ebcc25bb4983304c828fc1b151d90238f9c37e3ec13168` | 52,911,597 bytes | `root` (implicit) |
| Biometric | `ostrovua-biometric:audit-05b1600b-amd64-r2` | `sha256:458fce0a4d611ad3c95f554091cc02889765ff5e44b962b85c5aef85c6dc9b5f` | 552,678,422 bytes | `12001:12001` |

These are local Docker content digests. The release remains blocked until the
same artifacts are published to the controlled production registry and the
registry-qualified immutable digests are frozen in the deployment manifest.

The biometric image uses digest-pinned base images and executed
`BiometricEngine.from_environment()` during its build. The build completed with
`model integrity OK`.

## Model integrity

The exported biometric image was started with a read-only root filesystem,
all capabilities dropped, `no-new-privileges`, a 64-process limit, a 2 GiB
memory limit, no network, and a non-executable temporary filesystem.

The model files inside the exported image matched the frozen manifest:

| Model | SHA-256 |
|---|---|
| `face_landmarker.task` | `64184e229b263107bc2b804c6625db1341ff2bb731874b0bcc2fe6544e0bc9ff` |
| `minifas_v1se_4_0.onnx` | `3d83e0966d3219b68192f1940d1f2dd7421e4ad9c4620259a8654e6c1366021a` |
| `minifas_v2_2_7.onnx` | `19a7599b74c27416f1f153a5a7159eda9f046a720f2ec251f39926921f555a87` |
| `sface.onnx` | `0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79` |
| `yunet.onnx` | `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4` |

Native imports for NumPy, OpenCV, ONNX Runtime, and MediaPipe succeeded.

## Pinned fixtures

| Fixture | Expected class | SHA-256 |
|---|---|---|
| `image_T1.jpg` | live | `f4455149f488f76205fdee5499ec5261d08ef6279a1cff7b778ea85405331e94` |
| `image_F1.jpg` | print spoof | `4b11b5d7a8a8e4a88f5f16a5426a0a7692e39e5bb45bb03b4ebe5e1606336860` |
| `image_F2.jpg` | screen spoof | `fbbea73450ae9d9bb555c8ccac77bf39d234261fe3be4190e3ed2999690c485f` |

## Results

`Server/biometric_service/tests/test_model_smoke.py` passed both tests:

- pinned model set loads: passed
- live fixture separates from print and screen spoofs: passed
- total: 2 passed, 0 failed, 0 skipped

Observed scores:

| Input | PAD score |
|---|---:|
| live (`image_T1.jpg`) | `0.999879` |
| print spoof (`image_F1.jpg`) | `0.228581` |
| screen spoof (`image_F2.jpg`) | `0.002344` |

The runtime model-set hash was
`291e044feb6c53e2ac9903094bcffd8a20519ef0ee1391c51c0c956ea771c0d0`.
`calibration_approved` was `False`.

The auth image was also started with no network, a read-only root filesystem,
all capabilities dropped, and `no-new-privileges`. Node.js `v20.20.2` parsed
all 11 runtime JavaScript files with `node --check`.

## Residual risks and release decision

- The auth image still runs as root because its Dockerfile has no explicit
  non-root `USER`.
- The local Docker content digests are not yet registry-qualified production
  digests.
- This small upstream smoke set proves model loading and a basic live/spoof
  separation only. It does not replace independent APCER/BPCER/FMR/FNMR
  calibration.
- The real AA/CA/passive document corpus, independent cryptographic review,
  independent biometric calibration, and signed calibration report remain
  incomplete.

Release decision remains **NO-GO**. This run closes only the previously pending
model-smoke gate for the locally built final images.
