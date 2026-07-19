#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════
#  Розбирає CscaMasterList (ICAO Doc 9303) на окремі сертифікати.
#
#  Вхід:  DER-файл вмісту masterlist (те, що віддав
#         `openssl cms -verify -noverify -out content.der`)
#  Вихід: certs/cert_NNN.pem (усі, з дедуплікацією за SHA-256)
#
#  CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }
# ═══════════════════════════════════════════════════════════════════
import base64
import hashlib
import os
import sys


def tlv(buf, off):
    """Читає один DER TLV. Повертає (перший_байт, початок_вмісту, кінець)."""
    first = buf[off]
    p = off + 1
    if (first & 0x1F) == 0x1F:  # багатобайтовий тег
        while buf[p] & 0x80:
            p += 1
        p += 1
    ln = buf[p]
    p += 1
    if ln >= 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise ValueError("BER/задовга довжина не підтримується")
        ln = int.from_bytes(buf[p:p + n], "big")
        p += n
    if p + ln > len(buf):
        raise ValueError("довжина за межами буфера")
    return first, p, p + ln


def children(buf, start, end):
    out = []
    p = start
    while p < end:
        first, cs, ce = tlv(buf, p)
        out.append((first, p, cs, ce))
        p = ce
    return out


def main():
    if len(sys.argv) < 3:
        print("Використання: extract_certs.py <content.der> <тека_виводу>")
        sys.exit(1)

    data = open(sys.argv[1], "rb").read()
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    first, cs, ce = tlv(data, 0)
    if first == 0x30:  # SEQUENCE { version, SET }
        kids = children(data, cs, ce)
        certset = next((k for k in kids if k[0] == 0x31), None)
        if certset is None:
            raise SystemExit("✗ Не знайшов SET OF Certificate всередині SEQUENCE")
        _, _, cs, ce = certset
    elif first == 0x31:  # одразу SET OF Certificate
        pass
    else:
        raise SystemExit(f"✗ Несподіваний зовнішній тег 0x{first:02x}")

    seen = set()
    count = 0
    for cfirst, cstart, _, cend in children(data, cs, ce):
        if cfirst != 0x30:  # Certificate — SEQUENCE
            continue
        der = data[cstart:cend]
        fp = hashlib.sha256(der).hexdigest()
        if fp in seen:
            continue
        seen.add(fp)
        count += 1
        b64 = base64.encodebytes(der).decode().rstrip("\n")
        with open(os.path.join(outdir, f"cert_{count:03d}.pem"), "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\n")
            f.write(b64 + "\n")
            f.write("-----END CERTIFICATE-----\n")

    print(f"✓ Витягнуто сертифікатів: {count} (унікальних)")


if __name__ == "__main__":
    main()
