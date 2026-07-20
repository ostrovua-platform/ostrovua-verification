#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  РЕАЛЬНИЙ concurrency-тест verify_bind_document проти ЖИВОГО Postgres
#  (аудит #9). Запускає N ПАРАЛЕЛЬНИХ окремих зʼєднань (docker exec
#  psql), кожне клеймить ОДИН і той самий токен від різного акаунта.
#  Доводить: рядковий замок (SELECT … FOR UPDATE) серіалізує гонку —
#  рівно один акаунт привʼязує токен і стає verified, решта → duplicate.
#
#  Тимчасові дані створюються й прибираються. Нічого прод-даних не чіпає.
#
#  Запуск НА СЕРВЕРІ:
#     cd /opt/ostrovua/backend && N=30 bash db/check_token_race.sh
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_hasura.sh"

N="${N:-30}"
TOKEN="racetest-$(date +%s)-$RANDOM"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pg() { docker exec -i "$PG_CONTAINER" psql -U ostrovua -d ostrovua -tA "$@"; }

echo "→ Функція наявна?"
HASFN=$(pg -c "SELECT count(*) FROM pg_proc WHERE proname='verify_bind_document';")
if [ "$HASFN" = "0" ]; then
  echo "✗ verify_bind_document немає. Спершу: bash db/apply_document_tokens.sh"
  exit 1
fi

echo "→ 1/4 Створюю $N тестових акаунтів"
pg -c "
INSERT INTO contributors(id,name,role,email,password_hash,status,description,consent_level)
SELECT gen_random_uuid(), 'racetest_'||g, 'Учасник',
       'racetest_'||g||'_${TOKEN}@test.local', 'x', 'active', '', 'none'
FROM generate_series(1,$N) g;" > /dev/null
pg -c "SELECT id FROM contributors WHERE email LIKE 'racetest_%_${TOKEN}@test.local';" > "$TMP/ids"
COUNT=$(wc -l < "$TMP/ids" | tr -d ' ')
echo "   створено: $COUNT"

echo "→ 2/4 $N паралельних клеймів одного токена (з барʼєром pg_sleep)"
i=0
while read -r ID; do
  [ -z "$ID" ] && continue
  # BEGIN + pg_sleep 0.5 → усі стартують майже одночасно → реальна
  # конкуренція на FOR UPDATE всередині verify_bind_document.
  ( pg -c "BEGIN; SELECT pg_sleep(0.5); \
           SELECT verify_bind_document('${TOKEN}', '${ID}'::uuid, \
             'nfc_passport+pa+depth', 'strong', now()); COMMIT;" \
      2>/dev/null | grep -E '^(ok|duplicate|banned)$' > "$TMP/res_$i" ) &
  i=$((i+1))
done < "$TMP/ids"
wait
echo "   завершено паралельних: $i"

echo "→ 3/4 Підрахунок"
OK=$(cat "$TMP"/res_* 2>/dev/null | grep -c '^ok$' || true)
DUP=$(cat "$TMP"/res_* 2>/dev/null | grep -c '^duplicate$' || true)
OWNERS=$(pg -c "SELECT count(*) FROM document_tokens WHERE token='${TOKEN}';")
VERIFIED=$(pg -c "
SELECT count(*) FROM contributors
WHERE email LIKE 'racetest_%_${TOKEN}@test.local'
  AND verified AND identity_assurance='strong';")

echo "   ok=$OK  duplicate=$DUP  token_owners=$OWNERS  verified=$VERIFIED"

echo "→ 4/4 Прибирання"
pg -c "DELETE FROM document_tokens WHERE token='${TOKEN}';" > /dev/null
pg -c "DELETE FROM contributors WHERE email LIKE 'racetest_%_${TOKEN}@test.local';" > /dev/null

echo
if [ "$OK" = "1" ] && [ "$DUP" = "$((COUNT-1))" ] && [ "$OWNERS" = "1" ] && [ "$VERIFIED" = "1" ]; then
  echo "✓ PASS — рівно один переможець; токен і verified узгоджені (одна транзакція)."
else
  echo "✗ FAIL — інваріант порушено (очікували ok=1, duplicate=$((COUNT-1)), owners=1, verified=1)."
  exit 1
fi
