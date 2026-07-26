#!/bin/sh
set -eu

destination="${1:-/tmp/ostrovua-biometric-smoke-fixtures}"
mkdir -p "$destination"

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

fetch() {
  url="$1"
  output="$2"
  expected="$3"
  temporary="${output}.partial"
  rm -f "$temporary"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    --output "$temporary" "$url"
  actual="$(digest "$temporary")"
  if [ "$actual" != "$expected" ]; then
    rm -f "$temporary"
    echo "fixture checksum mismatch: $output" >&2
    exit 1
  fi
  mv "$temporary" "$output"
}

commit="b6d5f04ad78778917853b25c778acef6d5626d15"
base="https://raw.githubusercontent.com/minivision-ai/Silent-Face-Anti-Spoofing/${commit}/images/sample"

fetch "$base/image_T1.jpg" "$destination/image_T1.jpg" \
  "f4455149f488f76205fdee5499ec5261d08ef6279a1cff7b778ea85405331e94"
fetch "$base/image_F1.jpg" "$destination/image_F1.jpg" \
  "4b11b5d7a8a8e4a88f5f16a5426a0a7692e39e5bb45bb03b4ebe5e1606336860"
fetch "$base/image_F2.jpg" "$destination/image_F2.jpg" \
  "fbbea73450ae9d9bb555c8ccac77bf39d234261fe3be4190e3ed2999690c485f"

echo "Pinned biometric smoke fixtures are ready in $destination"
