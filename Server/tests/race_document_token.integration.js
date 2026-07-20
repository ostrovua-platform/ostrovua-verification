// ═══════════════════════════════════════════════════════════════════
//  РЕАЛЬНИЙ PostgreSQL concurrency-тест (аудит #9): бʼє N паралельних
//  verify_bind_document() тим самим токеном з різних акаунтів проти
//  СПРАВЖНЬОЇ бази. Доводить, що рядковий замок (SELECT … FOR UPDATE)
//  серіалізує гонку: рівно один акаунт привʼязує токен і стає verified.
//
//  Запуск (стейдж/локальний Postgres):
//    npm i pg
//    PGHOST=… PGUSER=… PGPASSWORD=… PGDATABASE=… \
//      node Server/tests/race_document_token.integration.js
//
//  Тест сам створює тимчасові дані у транзакції-пісочниці й прибирає їх.
// ═══════════════════════════════════════════════════════════════════
'use strict';
const { Client, Pool } = require('pg');
const crypto = require('crypto');

const N = parseInt(process.env.N || '50', 10);
const TOKEN = 'test-' + crypto.randomBytes(8).toString('hex');

async function main() {
  const admin = new Client();
  await admin.connect();

  // Створюємо N тестових контрибʼюторів
  const ids = [];
  for (let i = 0; i < N; i++) {
    const r = await admin.query(
      `INSERT INTO contributors(id, name, email)
       VALUES (gen_random_uuid(), $1, $2) RETURNING id`,
      [`race_${i}`, `race_${i}_${TOKEN}@example.test`]
    );
    ids.push(r.rows[0].id);
  }

  // N паралельних клеймів одного токена (кожен — окреме зʼєднання)
  const pool = new Pool({ max: N });
  const at = new Date().toISOString();
  const results = await Promise.all(ids.map(async (cid) => {
    const c = await pool.connect();
    try {
      const r = await c.query(
        `SELECT verify_bind_document($1,$2,$3,$4,$5) AS out`,
        [TOKEN, cid, 'nfc_passport+pa+depth', 'strong', at]
      );
      return r.rows[0].out;
    } finally { c.release(); }
  }));
  await pool.end();

  // Перевірки інваріанта
  const oks = results.filter(x => x === 'ok').length;
  const dups = results.filter(x => x === 'duplicate').length;

  const owner = await admin.query(
    `SELECT contributor_id FROM document_tokens WHERE token=$1`, [TOKEN]);
  const verifiedCount = await admin.query(
    `SELECT count(*)::int AS n FROM contributors
     WHERE id = ANY($1) AND verified AND identity_assurance='strong'`, [ids]);

  const ownerId = owner.rows[0]?.contributor_id;
  const pass =
    oks === 1 &&
    dups === N - 1 &&
    owner.rows.length === 1 &&
    verifiedCount.rows[0].n === 1;

  console.log(`N=${N}: ok=${oks}, duplicate=${dups}`);
  console.log(`token owner rows=${owner.rows.length}, owner=${ownerId?.slice(0,8)}…`);
  console.log(`verified contributors=${verifiedCount.rows[0].n} (очікуємо рівно 1)`);
  console.log(pass ? '✓ PASS — рівно один переможець, contributor+token узгоджені'
                   : '✗ FAIL — інваріант порушено');

  // Прибирання
  await admin.query(`DELETE FROM document_tokens WHERE token=$1`, [TOKEN]);
  await admin.query(`DELETE FROM contributors WHERE id = ANY($1)`, [ids]);
  await admin.end();
  process.exit(pass ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(1); });
