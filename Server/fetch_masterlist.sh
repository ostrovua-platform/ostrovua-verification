#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  CSCA masterlist → csca_ua.pem (для Passive Authentication).
#
#  Запускається НА СЕРВЕРІ (deploy-меню, пункт 46). Порядок пошуку:
#   1. локальний файл *.ml / *.mls у цій теці (поклав вручну — беремо його);
#   2. інакше — скачує ОФІЦІЙНИЙ німецький BSI masterlist (HTTPS,
#      bsi.bund.de; ~490 КБ zip, всередині .ml). Джерело можна
#      замінити: ML_URL=... bash fetch_masterlist.sh
#
#  Інші офіційні джерела (якщо BSI недоступний):
#   • ICAO PKD: https://www.icao.int/icao-pkd/icao-master-list (за captcha)
#   • Нідерландський NPKD: https://www.npkd.nl
#
#  Що робить далі:
#   1. openssl cms -verify -noverify → дістає вміст CscaMasterList
#      і ДРУКУЄ, ким підписаний сам masterlist (перевір очима: BSI!);
#   2. extract_certs.py → окремі сертифікати;
#   3. фільтр C=UA → csca_ua.pem (довіряємо ЛИШЕ українським CSCA);
#      усі країни → csca_all.pem (про запас, не використовується).
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
cd "$(dirname "$0")"

# Офіційний німецький BSI CSCA Master List (Government Site Builder
# віддає актуальну версію; v=… у посиланні зростає з оновленнями).
ML_URL="${ML_URL:-https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.zip?__blob=publicationFile}"

ML="${1:-}"
if [ -z "$ML" ]; then
  ML=$(ls -1 ./*.ml ./*.mls 2>/dev/null | head -1 || true)
fi

# ── Немає локального файлу → скачуємо з BSI ─────────────────────────
if [ -z "$ML" ] || [ ! -f "$ML" ]; then
  echo "→ Локального *.ml немає — скачую офіційний BSI masterlist…"
  echo "  $ML_URL"
  rm -f bsi_masterlist.zip
  if command -v curl >/dev/null 2>&1; then
    curl -fL --max-time 120 -o bsi_masterlist.zip "$ML_URL"
  else
    wget -q -T 120 -O bsi_masterlist.zip "$ML_URL"
  fi

  SIZE=$(stat -c%s bsi_masterlist.zip 2>/dev/null || stat -f%z bsi_masterlist.zip)
  echo "→ Завантажено: $SIZE байт"
  if [ "$SIZE" -lt 100000 ]; then
    echo "✗ Файл підозріло малий (<100 КБ) — схоже, це не masterlist."
    echo "  Скачай вручну (джерела в шапці) і поклади *.ml у цю теку."
    exit 1
  fi

  rm -rf bsi_unzipped && mkdir bsi_unzipped
  python3 -m zipfile -e bsi_masterlist.zip bsi_unzipped/
  ML=$(find bsi_unzipped -iname "*.ml" -o -iname "*.mls" | head -1 || true)
  if [ -z "$ML" ]; then
    echo "✗ У zip не знайшовся *.ml. Вміст:"
    find bsi_unzipped -type f | sed 's/^/    /'
    exit 1
  fi
fi

echo "→ Masterlist: $ML"
rm -rf certs content.der ml_signer.pem
mkdir -p certs

# 1. Вміст + хто підписав сам masterlist (для контролю очима)
openssl cms -verify -noverify -inform DER -in "$ML" -out content.der \
  -signer ml_signer.pem 2>/dev/null \
  || openssl cms -verify -noverify -inform DER -in "$ML" -out content.der
if [ -f ml_signer.pem ]; then
  echo "→ Masterlist підписано:"
  openssl x509 -in ml_signer.pem -noout -subject -issuer | sed 's/^/    /'
fi

# 2. Окремі сертифікати
python3 extract_certs.py content.der certs

# 3. Фільтр: лише CSCA України (C=UA) → csca_ua.pem
: > csca_ua.pem
: > csca_all.pem
UA=0; ALL=0
for pem in certs/cert_*.pem; do
  SUBJ=$(openssl x509 -in "$pem" -noout -subject 2>/dev/null || echo "")
  cat "$pem" >> csca_all.pem; ALL=$((ALL+1))
  if echo "$SUBJ" | grep -Eq 'C ?= ?UA(,|/|$| )'; then
    cat "$pem" >> csca_ua.pem; UA=$((UA+1))
    echo "  UA: $SUBJ"
    openssl x509 -in "$pem" -noout -dates | sed 's/^/      /'
  fi
done

echo
echo "✓ Усього сертифікатів: $ALL, українських (C=UA): $UA"
if [ "$UA" -eq 0 ]; then
  echo "⚠ У цьому masterlist НЕМАЄ українських CSCA — PA не запрацює."
  echo "  Спробуй інше джерело (ICAO PKD містить UA)."
  exit 1
fi
echo "✓ csca_ua.pem готовий (монтується в auth як /app/csca/csca_ua.pem)."
