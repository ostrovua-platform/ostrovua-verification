#!/usr/bin/env python3
"""Build a DSC *lookup* bundle from active-all and an official ICAO PKD LDIF.

The output is deliberately not a trust store.  It only lets OpenSSL locate a
Document Signer Certificate when EF.SOD omits it.  Runtime still has to verify
the signer against the pinned CSCA bundle and independently enforce CRL or
fresh active-snapshot membership.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
from pathlib import Path
import re
import sys
import tempfile

from import_active_dsc import (
    ImportFailure,
    atomic_write,
    certificate_metadata,
    normalized_pem,
    openssl,
    parse_pins,
    pem_blocks,
    validate_ca_bundle,
    verify_leaf,
)


MAX_LDIF_BYTES = 256 * 1024 * 1024
MAX_CERT_BYTES = 128 * 1024
MAX_CANDIDATES = 10_000


def sha256_file(path: Path, maximum_bytes: int) -> str:
    size = path.stat().st_size
    if size <= 0 or size > maximum_bytes:
        raise ImportFailure(f"{path} size {size} is outside the accepted range")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_ldif_records(path: Path):
    """Yield unfolded records without loading the complete LDIF into RAM."""
    record: list[str] = []
    previous: str | None = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            if line.startswith(" ") and previous is not None:
                previous += line[1:]
                continue
            if previous is not None:
                if previous:
                    record.append(previous)
                elif record:
                    yield record
                    record = []
            previous = line
    if previous:
        record.append(previous)
    if record:
        yield record


def iter_ua_dsc_blobs(path: Path):
    count = 0
    for record in iter_ldif_records(path):
        dn = next(
            (line.split(":", 1)[1].strip() for line in record if line.lower().startswith("dn:")),
            "",
        )
        parts = set(re.split(r"(?<!\\),", dn.lower().replace(" ", "")))
        if "c=ua" not in parts or "o=dsc" not in parts:
            continue
        if {"o=bcsc", "o=bcsc-nc"} & parts:
            continue
        for line in record:
            match = re.match(r"(?i)^([^:]+)::\s*(.+)$", line)
            if not match:
                continue
            attribute, encoded = match.groups()
            attribute = attribute.lower()
            if "certificate" not in attribute or "revocation" in attribute:
                continue
            try:
                blob = base64.b64decode(encoded, validate=True)
            except ValueError:
                continue
            if not 0 < len(blob) <= MAX_CERT_BYTES:
                continue
            count += 1
            if count > MAX_CANDIDATES:
                raise ImportFailure("LDIF contains too many DSC candidates")
            yield f"ldif:{count}", blob


def has_digital_signature_usage(pem: bytes) -> bool:
    text = openssl(["x509", "-inform", "PEM", "-noout", "-text"], data=pem).decode(
        "utf-8", "replace"
    )
    usage = re.search(r"X509v3 Key Usage:.*?\n\s*([^\n]+)", text, re.DOTALL)
    return bool(usage and "Digital Signature" in usage.group(1))


def build(args: argparse.Namespace) -> dict[str, int | str]:
    ldif = Path(args.ldif).resolve()
    active = Path(args.active_bundle).resolve()
    ca_bundle = Path(args.ca_bundle).resolve()
    pins_path = Path(args.pins).resolve()
    output = Path(args.output).resolve()

    ldif_hash = sha256_file(ldif, MAX_LDIF_BYTES)
    active_hash = sha256_file(active, 8 * 1024 * 1024)
    if args.expected_ldif_sha256:
        expected = args.expected_ldif_sha256.lower().replace(":", "")
        if ldif_hash != expected:
            raise ImportFailure(
                f"LDIF SHA-256 mismatch: expected {expected}, received {ldif_hash}"
            )

    pins = parse_pins(pins_path)
    trusted_subjects = validate_ca_bundle(ca_bundle, pins)
    now = dt.datetime.now(dt.timezone.utc)
    accepted: dict[str, tuple[bytes, str, str]] = {}
    counters = {
        "active_accepted": 0,
        "ldif_accepted": 0,
        "duplicates": 0,
        "rejected": 0,
        "compatibility_fallbacks": 0,
    }

    with tempfile.TemporaryDirectory(prefix="dsc-lookup-") as temp_raw:
        temp = Path(temp_raw)

        def consider(label: str, raw: bytes, inform: str, required: bool) -> None:
            try:
                pem, der = normalized_pem(raw, inform)
                metadata = certificate_metadata(pem)
                if bool(metadata["declares_ca"]):
                    raise ImportFailure("candidate declares CA capability")
                if not has_digital_signature_usage(pem):
                    raise ImportFailure("candidate lacks digitalSignature key usage")
                not_before = metadata["not_before"]
                not_after = metadata["not_after"]
                assert isinstance(not_before, dt.datetime)
                assert isinstance(not_after, dt.datetime)
                if now < not_before or now > not_after:
                    raise ImportFailure("candidate is outside its validity interval")
                issuer = str(metadata["issuer"])
                if issuer not in trusted_subjects:
                    raise ImportFailure("issuer is not a pinned Ukrainian CSCA")
                fingerprint = hashlib.sha256(der).hexdigest()
                cert_path = temp / f"{fingerprint}.pem"
                cert_path.write_bytes(pem)
                used_fallback = verify_leaf(cert_path, ca_bundle, pins_path)
                if used_fallback:
                    counters["compatibility_fallbacks"] += 1
            except (ImportFailure, OSError, AssertionError) as exc:
                if required:
                    raise ImportFailure(f"{label}: {exc}") from exc
                counters["rejected"] += 1
                return

            if fingerprint in accepted:
                counters["duplicates"] += 1
                return
            accepted[fingerprint] = (pem, str(metadata["subject"]), label)
            counters["active_accepted" if required else "ldif_accepted"] += 1

        for index, block in enumerate(pem_blocks(active), 1):
            consider(f"active:{index}", block, "PEM", True)
        for label, blob in iter_ua_dsc_blobs(ldif):
            consider(label, blob, "DER", False)

    if len(accepted) < args.min_dsc:
        raise ImportFailure(
            f"validated only {len(accepted)} unique DSCs; minimum is {args.min_dsc}"
        )

    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    parts = [
        "# Generated by build_dsc_lookup.py; lookup material only, not a trust store.\n",
        f"# generated_at={generated}\n",
        f"# ldif_sha256={ldif_hash}\n",
        f"# active_sha256={active_hash}\n",
        f"# validated_dsc={len(accepted)}\n",
    ]
    for fingerprint in sorted(accepted):
        pem, subject, label = accepted[fingerprint]
        safe_subject = subject.replace("\r", " ").replace("\n", " ")
        parts.append(f"# dsc {fingerprint} source={label} subject={safe_subject}\n")
        parts.append(pem.decode("ascii"))
        if not parts[-1].endswith("\n"):
            parts.append("\n")
    if not args.dry_run:
        atomic_write(output, "".join(parts).encode("ascii"))

    return {
        **counters,
        "validated_dsc": len(accepted),
        "ldif_sha256": ldif_hash,
        "active_sha256": active_hash,
        "output": str(output),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("ldif", help="official ICAO PKD collection 001 complete LDIF")
    result.add_argument("--active-bundle", required=True)
    result.add_argument("--ca-bundle", required=True)
    result.add_argument("--pins", required=True)
    result.add_argument("--output", required=True)
    result.add_argument("--expected-ldif-sha256")
    result.add_argument("--min-dsc", type=int, default=90)
    result.add_argument("--dry-run", action="store_true")
    return result


def main() -> int:
    try:
        result = build(parser().parse_args())
    except (ImportFailure, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "OK: "
        f"validated={result['validated_dsc']} "
        f"active={result['active_accepted']} "
        f"ldif_added={result['ldif_accepted']} "
        f"duplicates={result['duplicates']} "
        f"rejected={result['rejected']} "
        f"compatibility_fallbacks={result['compatibility_fallbacks']}"
    )
    print(f"LDIF SHA-256: {result['ldif_sha256']}")
    print(f"Output: {result['output']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
