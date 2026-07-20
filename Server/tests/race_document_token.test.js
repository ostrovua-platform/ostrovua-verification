// ═══════════════════════════════════════════════════════════════════
//  Race-тест «1 документ = 1 акаунт» (аудит #4, P0-02).
//
//  Дві частини:
//   A. Модель інваріанта атомарного клейму (запускається будь-де,
//      без БД): симулює INSERT … ON CONFLICT … WHERE під конкуренцією
//      і доводить, що з N одночасних спроб різних акаунтів на ОДИН
//      документ рівно ОДНА привʼязується.
//   B. Реальний тест проти запущеного auth (потрібні 2 JWT + прод-БД):
//      див. коментар нижче — запускати на стейджі, не в CI.
//
//  Запуск моделі:  node Server/tests/race_document_token.test.js
// ═══════════════════════════════════════════════════════════════════
'use strict';

// ── A. Модель рядкового замка PostgreSQL на PK token ────────────────
// Один «рядок» document_tokens; конкуренти намагаються привʼязатись.
// Замок на PK серіалізує критичну секцію — саме це дає атомарність.
function makeDocumentRow() {
  let row = null;            // { contributor_id, status }
  let locked = false;
  return {
    // Емуляція INSERT … ON CONFLICT (token) DO UPDATE … WHERE (atomic)
    async claim(me) {
      // рядковий замок: критична секція виконується неподільно
      while (locked) await new Promise(r => setImmediate(r));
      locked = true;
      try {
        if (row === null) { row = { contributor_id: me, status: 'active' }; return me; }
        const canBind = (row.contributor_id === null || row.contributor_id === me)
                        && row.status === 'active';
        if (canBind) { row.contributor_id = me; return me; }
        return null;         // зайнятий іншим або забанений
      } finally { locked = false; }
    },
    owner() { return row?.contributor_id ?? null; },
  };
}

async function run() {
  let failures = 0;

  // Тест 1: 50 різних акаунтів одночасно клеймлять один документ
  {
    const doc = makeDocumentRow();
    const accounts = Array.from({ length: 50 }, (_, i) => 'acc_' + i);
    const results = await Promise.all(accounts.map(a => doc.claim(a)));
    const winners = results.filter(r => r !== null);
    const owner = doc.owner();
    const ok = winners.length === 1 && winners[0] === owner;
    console.log(`T1 50 паралельних клеймів → переможців: ${winners.length}, власник=${owner}: ${ok ? 'PASS' : 'FAIL'}`);
    if (!ok) failures++;
  }

  // Тест 2: власник повторно проходить верифікацію (ідемпотентно)
  {
    const doc = makeDocumentRow();
    await doc.claim('me');
    const again = await doc.claim('me');
    const ok = again === 'me' && doc.owner() === 'me';
    console.log(`T2 повторний клейм власником → ${again}: ${ok ? 'PASS' : 'FAIL'}`);
    if (!ok) failures++;
  }

  // Тест 3: чужий не може перехопити вже привʼязаний документ
  {
    const doc = makeDocumentRow();
    await doc.claim('owner');
    const thief = await doc.claim('thief');
    const ok = thief === null && doc.owner() === 'owner';
    console.log(`T3 чужий клейм привʼязаного → ${thief}, власник=${doc.owner()}: ${ok ? 'PASS' : 'FAIL'}`);
    if (!ok) failures++;
  }

  console.log(failures === 0 ? '\n✓ Інваріант атомарності підтверджено' : `\n✗ Провалів: ${failures}`);
  process.exit(failures === 0 ? 0 : 1);
}

// ── B. Реальний прод-тест (ручний, стейдж) ──────────────────────────
// 1) створи 2 тестові акаунти, отримай 2 JWT + зареєстровані App Attest
//    ключі; 2) підготуй валідну assertion над одним і тим самим SOD
//    (той самий документ); 3) вистрели N=20 паралельних POST
//    /auth/verify/approve з обох акаунтів; 4) очікування: рівно один
//    акаунт отримує 200 + verified, решта — 409/зайнятість; у
//    document_tokens один рядок, contributor_id одного переможця.
// (Не в CI: потрібні реальні пристрої/ключі й прод-БД.)

if (require.main === module) run();
module.exports = { makeDocumentRow };
