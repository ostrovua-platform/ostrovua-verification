#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  Незалежна звірка пінів UA CSCA за ДРУГИМ джерелом — слепком
#  ICAO PKD masterlist (репозиторій psvz/icao, знімок листопада 2022).
#
#  Навіщо: пін, звірений за двома незалежними джерелами (BSI ↔ ICAO),
#  виключає компрометацію одного джерела. Знімок 2022 підтвердить
#  CSCA 2015 і 2020 років; київські сертифікати 2024-го в ньому
#  ще відсутні — це ОЧІКУВАНО (вони лишаються звіреними лише BSI,
#  до наступного оновлення знімка ICAO).
#
#  Запуск НА СЕРВЕРІ: bash auth/csca/crosscheck_icao.sh [шлях-до-ldif]
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"

LDIF="${1:-}"
URL="${ICAO_LDIF_URL:-https://raw.githubusercontent.com/psvz/icao/master/icaopkd-002-ml-000216.ldif}"

rm -rf crosscheck && mkdir -p crosscheck

if [ -z "$LDIF" ]; then
  echo "→ Скачую знімок ICAO PKD masterlist…"
  echo "  $URL"
  curl -fL --max-time 180 -o crosscheck/icao.ldif "$URL"
  LDIF="crosscheck/icao.ldif"
fi

echo "→ LDIF: $LDIF ($(stat -c%s "$LDIF" 2>/dev/null || stat -f%z "$LDIF") байт)"

# 1. Дістаємо всі CscaMasterListData (base64, з переносами-продовженнями)
python3 - "$LDIF" << 'EOF'
import base64, sys

blobs, cur, collecting = [], [], False
for raw in open(sys.argv[1], 'r', errors='replace'):
    line = raw.rstrip('\n')
    if collecting and line.startswith(' '):
        cur.append(line[1:])
        continue
    if collecting:
        blobs.append(''.join(cur)); cur, collecting = [], False
    if line.startswith('CscaMasterListData::'):
        cur = [line.split('::', 1)[1].strip()]
        collecting = True
if collecting:
    blobs.append(''.join(cur))

for i, b in enumerate(blobs):
    open(f'crosscheck/ml_{i:02d}.der', 'wb').write(base64.b64decode(b))
print(f'✓ Masterlist-блобів у LDIF: {len(blobs)}')
EOF

# 2. Кожен блоб → сертифікати → фільтр C=UA → відбитки
: > crosscheck/ua_fingerprints.txt
for der in crosscheck/ml_*.der; do
  openssl cms -verify -noverify -inform DER -in "$der" -out "$der.content" 2>/dev/null || continue
  OUT="${der%.der}_certs"
  python3 extract_certs.py "$der.content" "$OUT" > /dev/null 2>&1 || continue
  for pem in "$OUT"/cert_*.pem; do
    [ -f "$pem" ] || continue
    SUBJ=$(openssl x509 -in "$pem" -noout -subject 2>/dev/null || echo "")
    if echo "$SUBJ" | grep -Eq 'C ?= ?UA(,|/|$| )'; then
      FP=$(openssl x509 -in "$pem" -noout -fingerprint -sha256 | sed 's/^.*=//' | tr -d ':' | tr 'A-F' 'a-f')
      echo "$FP  # $SUBJ" >> crosscheck/ua_fingerprints.txt
    fi
  done
done

sort -u crosscheck/ua_fingerprints.txt -o crosscheck/ua_fingerprints.txt
UA_ICAO=$(wc -l < crosscheck/ua_fingerprints.txt | tr -d ' ')
echo "✓ Українських CSCA у знімку ICAO PKD: $UA_ICAO"
echo

# 3. Звірка з pins_ua.txt
if [ ! -f pins_ua.txt ]; then
  echo "✗ pins_ua.txt відсутній — спершу зафіксуй піни (deploy п.46)."
  exit 1
fi

MATCH=0; MISS=0
while read -r line; do
  FP=$(echo "$line" | awk '{print $1}')
  case "$FP" in ''|\#*) continue ;; esac
  if grep -qi "^$FP" crosscheck/ua_fingerprints.txt; then
    echo "  ✓ ПІДТВЕРДЖЕНО ICAO: $line"
    MATCH=$((MATCH+1))
  else
    echo "  – немає у знімку ICAO 2022 (очікувано для сертифікатів 2024):"
    echo "      $line"
    MISS=$((MISS+1))
  fi
done < pins_ua.txt

echo
echo "Підсумок: підтверджено двома джерелами (BSI+ICAO): $MATCH, лише BSI: $MISS"
echo "Довідково: якщо 2015/2020 НЕ підтвердились — це тривога, перевіряй руками."
