#!/usr/bin/env python3
"""Build a validated Ukrainian DSC bundle from the official active-all.zip.

The ZIP itself is not a trust anchor.  Every current leaf certificate must build
directly to a CSCA certificate whose SHA-256 fingerprint is present in
``pins_ua.txt``.  Unknown roots, untrusted current leaves, malformed archives,
and suspiciously small results abort before the output file is replaced.

Only Python's standard library plus the server's ``openssl`` and ``node``
executables are required.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import zipfile


MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_ENTRIES = 2_000
MAX_CERT_BYTES = 128 * 1024
MAX_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----\s*",
    re.DOTALL,
)
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OPENSSL_BINARY = os.environ.get("OPENSSL_BIN", "openssl")
NODE_BINARY = os.environ.get("NODE_BIN", "node")
DIRECT_CHAIN_VALIDATOR = Path(__file__).with_name("validate_dsc_chain.js")
COMPATIBILITY_CHAIN_ERRORS = (
    "certificate public key has explicit ecc parameters",
    "unsupported or invalid name syntax",
)


class ImportFailure(RuntimeError):
    pass


def openssl(args: list[str], *, data: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            [OPENSSL_BINARY, *args],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise ImportFailure(f"{OPENSSL_BINARY} {' '.join(args)} timed out") from exc
    if proc.returncode != 0:
        detail_parts = [
            proc.stderr.decode("utf-8", "replace").strip(),
            proc.stdout.decode("utf-8", "replace").strip(),
        ]
        detail = " | ".join(part for part in detail_parts if part) or "unknown error"
        raise ImportFailure(f"{OPENSSL_BINARY} {' '.join(args)} failed: {detail}")
    return proc.stdout


def sha256_archive(path: Path) -> str:
    try:
        archive_size = path.stat().st_size
    except OSError as exc:
        raise ImportFailure(f"cannot stat archive {path}: {exc}") from exc
    if archive_size <= 0 or archive_size > MAX_ARCHIVE_BYTES:
        raise ImportFailure(f"archive size {archive_size} is outside the accepted range")

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ImportFailure(f"cannot read archive {path}: {exc}") from exc
    return digest.hexdigest()


def parse_pins(path: Path) -> set[str]:
    pins: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ImportFailure(f"cannot read pins file {path}: {exc}") from exc
    for line_no, raw in enumerate(lines, 1):
        value = raw.split("#", 1)[0].strip().lower().replace(":", "")
        if not value:
            continue
        if not HEX_SHA256_RE.fullmatch(value):
            raise ImportFailure(f"invalid SHA-256 pin at {path}:{line_no}")
        pins.add(value)
    if not pins:
        raise ImportFailure(f"no SHA-256 pins found in {path}")
    return pins


def parse_openssl_time(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z")
    except ValueError as exc:
        raise ImportFailure(f"cannot parse X.509 time {value!r}") from exc
    return parsed.replace(tzinfo=dt.timezone.utc)


def normalized_pem(der_or_pem: bytes, inform: str) -> tuple[bytes, bytes]:
    pem = openssl(["x509", "-inform", inform, "-outform", "PEM"], data=der_or_pem)
    der = openssl(["x509", "-inform", "PEM", "-outform", "DER"], data=pem)
    return pem, der


def certificate_metadata(pem: bytes) -> dict[str, object]:
    names = openssl(
        ["x509", "-inform", "PEM", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"],
        data=pem,
    ).decode("utf-8", "replace").splitlines()
    subject = next((line.split("=", 1)[1].strip() for line in names if line.startswith("subject=")), "")
    issuer = next((line.split("=", 1)[1].strip() for line in names if line.startswith("issuer=")), "")
    if not subject or not issuer:
        raise ImportFailure("certificate has no parseable subject/issuer")

    dates = openssl(
        ["x509", "-inform", "PEM", "-noout", "-startdate", "-enddate"], data=pem
    ).decode("ascii", "strict").splitlines()
    not_before_raw = next((line.split("=", 1)[1] for line in dates if line.startswith("notBefore=")), "")
    not_after_raw = next((line.split("=", 1)[1] for line in dates if line.startswith("notAfter=")), "")
    if not not_before_raw or not not_after_raw:
        raise ImportFailure("certificate has no parseable validity interval")

    text = openssl(["x509", "-inform", "PEM", "-noout", "-text"], data=pem).decode(
        "utf-8", "replace"
    )
    has_ca_true = bool(re.search(r"Basic Constraints:.*?CA:TRUE", text, re.DOTALL))
    has_cert_sign = bool(re.search(r"Key Usage:.*?Certificate Sign", text, re.DOTALL))
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": parse_openssl_time(not_before_raw),
        "not_after": parse_openssl_time(not_after_raw),
        "declares_ca": has_ca_true or has_cert_sign or subject == issuer,
    }


def pem_blocks(path: Path) -> list[bytes]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ImportFailure(f"cannot read PEM bundle {path}: {exc}") from exc
    blocks = PEM_RE.findall(data)
    if not blocks:
        raise ImportFailure(f"no certificates found in PEM bundle {path}")
    return blocks


def validate_ca_bundle(path: Path, pins: set[str]) -> set[str]:
    subjects: set[str] = set()
    seen: set[str] = set()
    for block in pem_blocks(path):
        pem, der = normalized_pem(block, "PEM")
        fingerprint = hashlib.sha256(der).hexdigest()
        if fingerprint not in pins:
            raise ImportFailure(
                f"CA bundle contains unpinned certificate {fingerprint}; refusing broader trust"
            )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        metadata = certificate_metadata(pem)
        if not bool(metadata["declares_ca"]):
            raise ImportFailure(
                f"pinned certificate {fingerprint} does not declare CA capability"
            )
        subjects.add(str(metadata["subject"]))
    if not subjects:
        raise ImportFailure("CA bundle is empty after validation")
    return subjects


def archive_entries(path: Path) -> list[tuple[str, bytes]]:
    try:
        archive_size = path.stat().st_size
    except OSError as exc:
        raise ImportFailure(f"cannot stat archive {path}: {exc}") from exc
    if archive_size <= 0 or archive_size > MAX_ARCHIVE_BYTES:
        raise ImportFailure(f"archive size {archive_size} is outside the accepted range")

    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ImportFailure(f"invalid ZIP archive {path}: {exc}") from exc

    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ENTRIES:
            raise ImportFailure(f"unexpected ZIP entry count: {len(infos)}")
        names: set[str] = set()
        total = 0
        result: list[tuple[str, bytes]] = []
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            mode = (info.external_attr >> 16) & 0xFFFF
            if (
                info.is_dir()
                or pure.is_absolute()
                or len(pure.parts) != 1
                or ".." in pure.parts
                or stat.S_ISLNK(mode)
            ):
                raise ImportFailure(f"unsafe ZIP entry: {name!r}")
            if name in names:
                raise ImportFailure(f"duplicate ZIP entry name: {name!r}")
            names.add(name)
            if pure.suffix.lower() not in {".cer", ".crt"}:
                raise ImportFailure(f"unexpected file type in ZIP: {name!r}")
            if info.flag_bits & 0x1:
                raise ImportFailure(f"encrypted ZIP entry is not accepted: {name!r}")
            if info.file_size <= 0 or info.file_size > MAX_CERT_BYTES:
                raise ImportFailure(f"suspicious certificate size for {name!r}: {info.file_size}")
            if info.compress_size == 0 or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO:
                raise ImportFailure(f"suspicious compression ratio for {name!r}")
            total += info.file_size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise ImportFailure("ZIP exceeds the uncompressed size limit")
            try:
                result.append((name, archive.read(info)))
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise ImportFailure(f"cannot read ZIP entry {name!r}: {exc}") from exc
        return result


def verify_leaf(cert_path: Path, ca_bundle: Path, pins_path: Path) -> bool:
    try:
        openssl(
            [
                "verify",
                "-purpose",
                "any",
                "-verify_depth",
                "1",
                "-CAfile",
                str(ca_bundle),
                str(cert_path),
            ]
        )
        return False
    except ImportFailure as openssl_error:
        detail = str(openssl_error).lower()
        if not any(marker in detail for marker in COMPATIBILITY_CHAIN_ERRORS):
            raise

    try:
        proc = subprocess.run(
            [
                NODE_BINARY,
                str(DIRECT_CHAIN_VALIDATOR),
                str(cert_path),
                str(ca_bundle),
                str(pins_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ImportFailure(f"direct DSC compatibility validation could not run: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip() or "unknown error"
        raise ImportFailure(f"direct DSC compatibility validation failed: {detail}")
    return True


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as handle:
            temp_name = handle.name
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
        temp_name = None
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def import_bundle(args: argparse.Namespace) -> dict[str, object]:
    archive = Path(args.archive).resolve()
    ca_bundle = Path(args.ca_bundle).resolve()
    pins_path = Path(args.pins).resolve()
    output = Path(args.output).resolve()
    archive_hash = sha256_archive(archive)
    if args.expected_sha256:
        expected = args.expected_sha256.lower().replace(":", "")
        if not HEX_SHA256_RE.fullmatch(expected):
            raise ImportFailure("--expected-sha256 must contain exactly 64 hex digits")
        if archive_hash != expected:
            raise ImportFailure(
                f"archive SHA-256 mismatch: expected {expected}, received {archive_hash}"
            )

    pins = parse_pins(pins_path)
    trusted_subjects = validate_ca_bundle(ca_bundle, pins)
    entries = archive_entries(archive)
    now = dt.datetime.now(dt.timezone.utc)
    accepted: dict[str, tuple[bytes, str, str]] = {}
    counters = {
        "source_entries": len(entries),
        "source_expired": 0,
        "source_not_yet_valid": 0,
        "source_anchors": 0,
        "source_duplicates": 0,
        "compatibility_fallbacks": 0,
        "existing_accepted": 0,
        "existing_skipped": 0,
    }

    with tempfile.TemporaryDirectory(prefix="active-dsc-") as tmp_raw:
        tmp = Path(tmp_raw)

        def consider(label: str, raw: bytes, inform: str, source_is_archive: bool) -> None:
            try:
                pem, der = normalized_pem(raw, inform)
                metadata = certificate_metadata(pem)
            except ImportFailure as exc:
                raise ImportFailure(f"{label}: {exc}") from exc
            fingerprint = hashlib.sha256(der).hexdigest()
            not_before = metadata["not_before"]
            not_after = metadata["not_after"]
            assert isinstance(not_before, dt.datetime) and isinstance(not_after, dt.datetime)
            if now < not_before:
                if source_is_archive:
                    counters["source_not_yet_valid"] += 1
                else:
                    counters["existing_skipped"] += 1
                return
            if now > not_after:
                if source_is_archive:
                    counters["source_expired"] += 1
                else:
                    counters["existing_skipped"] += 1
                return

            declares_ca = bool(metadata["declares_ca"])
            if declares_ca or fingerprint in pins:
                if fingerprint not in pins:
                    raise ImportFailure(
                        f"{label}: current CA/link certificate {fingerprint} is not pinned"
                    )
                if source_is_archive:
                    counters["source_anchors"] += 1
                return

            issuer = str(metadata["issuer"])
            if issuer not in trusted_subjects:
                raise ImportFailure(f"{label}: issuer is not a pinned Ukrainian CSCA: {issuer}")

            cert_path = tmp / f"{fingerprint}.pem"
            cert_path.write_bytes(pem)
            try:
                used_compatibility_fallback = verify_leaf(cert_path, ca_bundle, pins_path)
            except ImportFailure as exc:
                raise ImportFailure(f"{label}: DSC chain validation failed: {exc}") from exc
            if used_compatibility_fallback:
                counters["compatibility_fallbacks"] += 1

            if fingerprint in accepted:
                if source_is_archive:
                    counters["source_duplicates"] += 1
                return
            accepted[fingerprint] = (pem, str(metadata["subject"]), label)
            if not source_is_archive:
                counters["existing_accepted"] += 1

        for name, raw in entries:
            consider(f"archive:{name}", raw, "DER", True)

        if args.merge_existing and output.exists():
            for index, block in enumerate(pem_blocks(output), 1):
                consider(f"existing:{index}", block, "PEM", False)

    if len(accepted) < args.min_dsc:
        raise ImportFailure(
            f"validated only {len(accepted)} DSCs; minimum required is {args.min_dsc}"
        )

    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    output_parts = [
        "# Generated by import_active_dsc.py; do not edit manually.\n",
        f"# generated_at={generated}\n",
        f"# source_sha256={archive_hash}\n",
        f"# validated_dsc={len(accepted)}\n",
    ]
    for fingerprint in sorted(accepted):
        pem, subject, label = accepted[fingerprint]
        safe_subject = subject.replace("\n", " ").replace("\r", " ")
        output_parts.append(f"# dsc {fingerprint} source={label} subject={safe_subject}\n")
        output_parts.append(pem.decode("ascii"))
        if not output_parts[-1].endswith("\n"):
            output_parts.append("\n")
    output_data = "".join(output_parts).encode("ascii")
    if not args.dry_run:
        atomic_write(output, output_data)

    counters.update(
        {
            "archive_sha256": archive_hash,
            "validated_dsc": len(accepted),
            "output": str(output),
            "dry_run": bool(args.dry_run),
        }
    )
    return counters


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="path to the official active-all.zip")
    parser.add_argument("--ca-bundle", required=True, help="PEM bundle containing pinned UA CSCAs")
    parser.add_argument("--pins", required=True, help="pins_ua.txt with allowed CSCA SHA-256 hashes")
    parser.add_argument("--output", required=True, help="target dsc_ua.pem")
    parser.add_argument(
        "--expected-sha256",
        help="optional archive checksum; mismatch aborts before validation",
    )
    parser.add_argument(
        "--merge-existing",
        action="store_true",
        help="merge still-valid DSCs already present in the output bundle",
    )
    parser.add_argument(
        "--min-dsc",
        type=int,
        default=50,
        help="minimum validated unique DSC count required for replacement (default: 50)",
    )
    parser.add_argument("--dry-run", action="store_true", help="validate and report without writing")
    parser.add_argument(
        "--openssl",
        default=OPENSSL_BINARY,
        help="OpenSSL executable (or set OPENSSL_BIN; OpenSSL 3 is recommended)",
    )
    parser.add_argument(
        "--node",
        default=NODE_BINARY,
        help="Node.js executable used for the narrow ICAO compatibility verifier",
    )
    return parser


def main() -> int:
    global NODE_BINARY, OPENSSL_BINARY
    parser = build_parser()
    args = parser.parse_args()
    OPENSSL_BINARY = args.openssl
    NODE_BINARY = args.node
    if args.min_dsc < 1:
        parser.error("--min-dsc must be positive")

    output = Path(args.output).resolve()
    lock_path = output.with_name(f".{output.name}.import.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            result = import_bundle(args)
    except (ImportFailure, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"archive_sha256={result['archive_sha256']}")
    print(f"source_entries={result['source_entries']}")
    print(f"source_expired={result['source_expired']}")
    print(f"source_not_yet_valid={result['source_not_yet_valid']}")
    print(f"source_anchors={result['source_anchors']}")
    print(f"source_duplicates={result['source_duplicates']}")
    print(f"compatibility_fallbacks={result['compatibility_fallbacks']}")
    print(f"existing_accepted={result['existing_accepted']}")
    print(f"existing_skipped={result['existing_skipped']}")
    print(f"validated_dsc={result['validated_dsc']}")
    print(f"output={result['output']}")
    print(f"dry_run={str(result['dry_run']).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
