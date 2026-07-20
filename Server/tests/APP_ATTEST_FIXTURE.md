# Реальна assertion-фікстура тестового iPhone (аудит #2)

Мета: дати аудитору ground-truth для перевірки App Attest, а не
виводити фікстуру зі спеки (звідси хибний висновок про «double hash» —
див. нижче). Формула сервера ЕМПІРИЧНО коректна: реальні assertion
з iPhone проходять у продакшені (лог `level=strong pa=passed`).

## Що таке «double hash» і чому це НЕ баг

`verifyAssertion` рахує:
```
clientDataHash = SHA256(challenge ‖ rawBody)
nonce          = SHA256(authenticatorData ‖ clientDataHash)
verify: ECDSA-SHA256(publicKey, message = nonce, signature)   // тобто e = SHA256(nonce)
```
Пристрій Apple підписує nonce як повідомлення через ECDSA-with-SHA256,
тож верифікатор ХЕШУЄ nonce ще раз — це і є коректний потік
(де-факто стандарт: `createVerify('SHA256').update(nonce)`).
Якби був зайвий хеш, ЖОДНА справжня assertion не пройшла б — а вони
проходять. Фікстура нижче це формалізує.

## Як зняти фікстуру (Dani, з реального iPhone)

1. Тимчасово увімкни у DEBUG-збірці лог у `AppAttestService`
   (одразу після формування assertion) — дамп у консоль base64:
   ```
   challengeB64, keyId, canonicalPayload (rawBody), assertionB64
   ```
   та публічний ключ з БД (`attest_keys.public_key_pem` цього keyId).
2. Пройди верифікацію один раз на пристрої.
3. Скопіюй значення у `fixture.json`:
   ```json
   {
     "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n…",
     "challengeB64": "…",
     "bodyB64": "…",          // Base64(rawBody) — дослівні байти тіла
     "assertionB64": "…",
     "expectedCounter": 1
   }
   ```
4. Прогін проти реального верифікатора:
   ```
   node Server/tests/verify_fixture.js fixture.json
   → expect: signature VALID, counter accepted
   ```
5. Прибери DEBUG-лог. **Не комітити fixture.json з реальним keyId**
   у публічний репозиторій (це прив'язка до конкретного пристрою) —
   надіслати аудитору приватно.

Скрипт `verify_fixture.js` використовує ТОЙ САМИЙ `appattest.js`,
що й продакшн, тож підтверджує коректність без прод-БД.
