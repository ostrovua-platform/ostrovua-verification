#!/usr/bin/env python3
"""Build a hash-only release evidence manifest.

The default mode refuses a dirty Git tree.  Output should be written outside
the repository so generating the manifest cannot change the object being
frozen.  Secrets and environment values are never collected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SERVICE = Path(__file__).resolve().parents[1] / "biometric_service"
sys.path.insert(0, str(SERVICE))

from policy import POLICY_VERSION, policy_parameters  # noqa: E402


SCHEMA = "ostrovua-release-evidence-v1"
LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DEFAULT_ARTIFACTS = {
    "biometric-policy": "Server/biometric_service/policy.py",
    "biometric-evaluator": "Server/biometric_service/evaluate.py",
    "calibration-verifier": "Server/biometric_service/calibration.py",
    "biometric-model-manifest": "Server/biometric_service/model_manifest.json",
    "biometric-requirements": "Server/biometric_service/requirements.txt",
    "biometric-dockerfile": "Server/biometric_service/Dockerfile",
    "active-authentication": "Server/biometric_service/document_auth.py",
    "chip-authentication": "Server/document_ca.js",
    "auth-package-lock": "Server/package-lock.json",
    "auth-dockerfile": "Server/Dockerfile",
    "nginx-config": "Server/nginx/nginx.conf",
}


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_mapping(values: list[str], kind: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        label, separator, target = value.partition("=")
        if separator != "=" or LABEL_RE.fullmatch(label) is None or not target:
            raise ValueError(f"{kind}_mapping_invalid")
        if label in parsed:
            raise ValueError(f"{kind}_label_duplicate")
        parsed[label] = target
    return parsed


def build_manifest(repo: Path, *, artifacts: dict[str, str],
                   images: dict[str, str], allow_dirty: bool = False) -> dict[str, Any]:
    repo = repo.resolve()
    if Path(_git(repo, "rev-parse", "--show-toplevel")).resolve() != repo:
        raise ValueError("repo_root_required")
    status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    clean = status == ""
    if not clean and not allow_dirty:
        raise ValueError("git_tree_dirty")

    artifact_manifest: dict[str, Any] = {}
    for label, configured_path in sorted(artifacts.items()):
        if LABEL_RE.fullmatch(label) is None:
            raise ValueError("artifact_label_invalid")
        candidate = (repo / configured_path).resolve()
        try:
            relative = candidate.relative_to(repo)
        except ValueError as error:
            raise ValueError(f"artifact_outside_repo:{label}") from error
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"artifact_invalid:{label}")
        artifact_manifest[label] = {
            "path": relative.as_posix(),
            "sha256": _sha256(candidate),
            "bytes": candidate.stat().st_size,
        }

    image_manifest: dict[str, str] = {}
    for label, digest in sorted(images.items()):
        if LABEL_RE.fullmatch(label) is None or IMAGE_RE.fullmatch(digest) is None:
            raise ValueError(f"image_invalid:{label}")
        image_manifest[label] = digest

    model_manifest_path = repo / "Server/biometric_service/model_manifest.json"
    model_manifest = json.loads(model_manifest_path.read_text(encoding="utf-8"))
    canonical_models = json.dumps(
        model_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")

    return {
        "schema": SCHEMA,
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "git": {
            "commit": _git(repo, "rev-parse", "HEAD"),
            "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD"),
            "clean": clean,
            "dirtyEntryCount": 0 if clean else len(status.splitlines()),
        },
        "modelSetHash": hashlib.sha256(canonical_models).hexdigest(),
        "policyVersion": POLICY_VERSION,
        "policyParameters": policy_parameters(),
        "artifacts": artifact_manifest,
        "images": image_manifest,
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact", action="append", default=[],
                        metavar="LABEL=PATH")
    parser.add_argument("--image", action="append", default=[],
                        metavar="LABEL=SHA256_DIGEST")
    parser.add_argument("--allow-dirty", action="store_true",
                        help="rehearsal only; resulting manifest cannot approve production")
    args = parser.parse_args()

    repo = args.repo.resolve()
    output = args.output.resolve()
    if output == repo or repo in output.parents:
        raise ValueError("output_must_be_outside_repo")

    artifacts = dict(DEFAULT_ARTIFACTS)
    artifacts.update(_parse_mapping(args.artifact, "artifact"))
    images = _parse_mapping(args.image, "image")
    manifest = build_manifest(
        repo,
        artifacts=artifacts,
        images=images,
        allow_dirty=args.allow_dirty,
    )
    encoded = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _atomic_write(output, encoded)
    print(json.dumps({
        "output": str(output),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "clean": manifest["git"]["clean"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
