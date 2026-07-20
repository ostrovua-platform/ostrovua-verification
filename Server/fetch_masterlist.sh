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

# ── Захист від ВІДКАТУ (аудит P1-11): signingTime нового masterlist
# не може бути старішим за вже застосований. Стан — ml_state.txt
# (генерується на сервері, виключений з rsync).
ML_TIME_RAW=$(openssl cms -inform DER -in "$ML" -cmsout -print 2>/dev/null \
  | grep -A2 'signingTime' | grep -m1 'UTCTIME\|GENERALIZEDTIME' \
  | sed 's/.*TIME://')
if [ -n "$ML_TIME_RAW" ]; then
  ML_EPOCH=$(date -d "$ML_TIME_RAW" +%s 2>/dev/null || echo "")
  if [ -n "$ML_EPOCH" ] && [ -f ml_state.txt ]; then
    PREV_EPOCH=$(head -1 ml_state.txt)
    if [ "$ML_EPOCH" -lt "$PREV_EPOCH" ] && [ "${FORCE_ML:-0}" != "1" ]; then
      echo "✗ ВІДКАТ: цей masterlist ($ML_TIME_RAW) старіший за застосований"
      echo "  ($(date -d @"$PREV_EPOCH" 2>/dev/null || echo "$PREV_EPOCH"))."
      echo "  Свідомо прийняти старіший: FORCE_ML=1. Інакше — СТОП."
      exit 1
    fi
  fi
  echo "→ Підписано: $ML_TIME_RAW"
else
  echo "⚠ Не зміг прочитати signingTime — захист від відкату пропущено."
fi

rm -rf certs content.der ml_signer.pem
mkdir -p certs

fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/^.*=//' | tr -d ':' | tr 'A-F' 'a-f'
}

# 1. Вміст + підписант. БЕЗ fallback (аудит P1-03): раніше друга
# спроба без -signer могла лишити ml_signer.pem відсутнім і ТИХО
# пропустити перевірку піна підписанта. Тепер: не витягли підписанта —
# СТОП, жодного шляху повз пін.
if ! openssl cms -verify -noverify -inform DER -in "$ML" -out content.der \
     -signer ml_signer.pem 2>/dev/null; then
  echo "✗ Не вдалося перевірити CMS-підпис / витягти підписанта masterlist. СТОП."
  exit 1
fi
if [ ! -f ml_signer.pem ]; then
  echo "✗ Підписанта не витягнуто — перевірка піна неможлива. СТОП."
  exit 1
fi
if [ -f ml_signer.pem ]; then
  echo "→ Masterlist підписано:"
  openssl x509 -in ml_signer.pem -noout -subject -issuer | sed 's/^/    /'

  # ── ПІН підписанта masterlist ─────────────────────────────────────
  # pins_ml_signer.txt (у git, синхронізується з Мака) фіксує SHA-256
  # відбиток сертифіката підписанта BSI. Якщо відбиток змінився —
  # або BSI ротував ключ (звір з другим джерелом і онови пін),
  # або джерело підмінено. У сумніві НЕ оновлюй пін.
  MLFP=$(fingerprint ml_signer.pem)
  echo "$MLFP  # $(openssl x509 -in ml_signer.pem -noout -subject | sed 's/^subject=//')" > pins_ml_signer.generated.txt
  if [ -f pins_ml_signer.txt ]; then
    if grep -qi "$MLFP" pins_ml_signer.txt; then
      echo "  ✓ Відбиток підписанта збігається з піном"
    else
      echo "  ✗ ВІДБИТОК ПІДПИСАНТА НЕ ЗБІГАЄТЬСЯ З ПІНОМ!"
      echo "    очікували: $(cat pins_ml_signer.txt | tr '\n' ' ')"
      echo "    отримали:  $MLFP"
      echo "    Джерело могло бути підмінено. СТОП."
      exit 1
    fi
  elif [ "${ALLOW_TOFU:-0}" = "1" ]; then
    echo "  ⚠ Піна підписанта ще немає (TOFU-режим). Відбиток:"
    echo "    $MLFP"
    echo "    Записано в pins_ml_signer.generated.txt — забери на Мак як pins_ml_signer.txt."
  else
    echo "  ✗ pins_ml_signer.txt відсутній, TOFU не дозволено. СТОП."
    exit 1
  fi
fi

# 2. Окремі сертифікати
python3 extract_certs.py content.der certs

# 3. Фільтр: лише CSCA України (C=UA) → csca_ua.pem — З ПІНАМИ.
#
#    pins_ua.txt (у git, синхронізується з Мака) — SHA-256 відбитки
#    ДОВІРЕНИХ українських CSCA. Якщо файл є, у csca_ua.pem потрапляють
#    ЛИШЕ запінені сертифікати: новий/чужий CSCA у masterlist не стане
#    коренем довіри мовчки. Новий легітимний UA CSCA додається так:
#    звір відбиток за ДРУГИМ незалежним джерелом (ICAO PKD, npkd.nl),
#    допиши рядок у pins_ua.txt, задеплой.
# Збірка у тимчасові файли; РОБОЧИЙ csca_ua.pem підміняється атомарно
# (mv) лише наприкінці (аудит P1-02): auth ніколи не читає недописаний
# або порожній trust bundle.
: > csca_ua.pem.new
: > csca_all.pem.new
: > pins_ua.generated.txt
UA=0; ALL=0; SKIPPED=0
HAVE_PINS=0
[ -f pins_ua.txt ] && HAVE_PINS=1

# FAIL-CLOSED BOOTSTRAP: без pins_ua.txt довіру НЕ будуємо. TOFU
# (перший запуск з фіксацією нових пінів) — ЛИШЕ явним ALLOW_TOFU=1,
# і ЛИШЕ на ще не ініціалізованій системі (аудит P1-01: на робочому
# проді TOFU не спрацює навіть з прапорцем — це не escape hatch).
if [ "$HAVE_PINS" = "0" ]; then
  if [ "${ALLOW_TOFU:-0}" != "1" ]; then
    echo "✗ pins_ua.txt відсутній. Довіра без пінів НЕ встановлюється."
    echo "  Свідомий ПЕРШИЙ запуск нової системи: ALLOW_TOFU=1 bash auth/csca/fetch_masterlist.sh"
    echo "  Потім: звір відбитки за другим джерелом і зафіксуй pins_ua.txt у git."
    exit 1
  fi
  if [ -f ml_state.txt ] || [ -f csca_ua.pem ]; then
    echo "✗ Система вже ініціалізована — TOFU заборонено. Поверни pins_ua.txt з git."
    exit 1
  fi
fi

for pem in certs/cert_*.pem; do
  SUBJ=$(openssl x509 -in "$pem" -noout -subject 2>/dev/null || echo "")
  cat "$pem" >> csca_all.pem.new; ALL=$((ALL+1))
  if echo "$SUBJ" | grep -Eq 'C ?= ?UA(,|/|$| )'; then
    FP=$(fingerprint "$pem")
    echo "$FP  # $SUBJ" >> pins_ua.generated.txt
    if [ "$HAVE_PINS" = "1" ] && ! grep -qi "$FP" pins_ua.txt; then
      SKIPPED=$((SKIPPED+1))
      echo "  ⚠ UA-сертифікат НЕ в pins_ua.txt — ПРОПУЩЕНО:"
      echo "      $SUBJ"
      echo "      відбиток: $FP"
      continue
    fi
    cat "$pem" >> csca_ua.pem.new; UA=$((UA+1))
    echo "  UA: $SUBJ"
    openssl x509 -in "$pem" -noout -dates | sed 's/^/      /'
    echo "      sha256: $FP"
  fi
done

echo
echo "✓ Усього сертифікатів: $ALL, українських у довірі: $UA (пропущено непінованих: $SKIPPED)"
if [ "$HAVE_PINS" = "0" ]; then
  echo
  echo "⚠ ПІНІВ ЩЕ НЕМАЄ (перший запуск). Зафіксуй корені довіри:"
  echo "  1) звір відбитки вище з другим джерелом (ICAO PKD / npkd.nl);"
  echo "  2) скопіюй pins_ua.generated.txt → backend/auth/csca/pins_ua.txt на Маку"
  echo "     (scp $(hostname):$(pwd)/pins_ua.generated.txt …/pins_ua.txt);"
  echo "  3) закоміть у git і задеплой — далі довіра ЗАКРІПЛЕНА."
fi
if [ "$UA" -eq 0 ]; then
  echo "✗ Жодного довіреного українського CSCA — PA не запрацює."
  [ "$SKIPPED" -gt 0 ] && echo "  Усі UA-сертифікати відсіяні пінами. Перевір pins_ua.txt!"
  rm -f csca_ua.pem.new csca_all.pem.new
  exit 1
fi

# АТОМАРНА ПІДМІНА (mv у межах однієї ФС — атомарний rename):
# робочий trust bundle або старий цілий, або новий цілий — ніколи
# не порожній і не недописаний.
mv csca_ua.pem.new csca_ua.pem
mv csca_all.pem.new csca_all.pem
echo "✓ csca_ua.pem готовий (монтується в auth як /app/csca/csca_ua.pem)."

# Фіксуємо застосовану версію (для захисту від відкату наступного разу)
if [ -n "${ML_EPOCH:-}" ]; then
  printf "%s\n# applied %s (%s)\n" "$ML_EPOCH" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ML_TIME_RAW" > ml_state.txt
fi
