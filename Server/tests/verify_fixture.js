// Перевірка реальної assertion-фікстури ТИМ САМИМ верифікатором,
// що й продакшн (аудит #2). Використання:
//   node Server/tests/verify_fixture.js fixture.json
//
// fixture.json: { publicKeyPem, challengeB64, bodyB64, assertionB64, expectedCounter }
'use strict';
const fs = require('fs');
const path = require('path');

// Той самий модуль, що у проді (шлях відносно репозиторію).
const appattest = require(path.join(__dirname, '..', 'appattest.js'));

const f = JSON.parse(fs.readFileSync(process.argv[2] || 'fixture.json', 'utf8'));

try {
  const counter = appattest.verifyAssertion({
    assertionB64: f.assertionB64,
    publicKeyPem: f.publicKeyPem,
    challengeBytes: Buffer.from(f.challengeB64, 'base64'),
    bodyBytes: Buffer.from(f.bodyB64, 'base64'),
    storedCounter: (f.expectedCounter ?? 1) - 1,
  });
  console.log('✓ signature VALID, newCounter =', counter);
  if (f.expectedCounter != null && counter !== f.expectedCounter) {
    console.log('⚠ counter != expected (' + f.expectedCounter + ')');
    process.exit(2);
  }
  process.exit(0);
} catch (e) {
  console.error('✗ verification FAILED:', e.message);
  process.exit(1);
}
