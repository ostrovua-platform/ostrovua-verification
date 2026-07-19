# OstrovUA — модуль верифікації (Verified ID)

Відкритий вихідний код модуля верифікації застосунку **OstrovUA** —
спільноти українців із підтвердженням особи за біометричним паспортом.

Публікуємо цей код з однією метою: **щоб кожен міг перевірити,
що паспортні дані не збираються і не покидають телефон.**

## Головна гарантія приватності

Паспортні дані НЕ передаються на сервер і не покидають телефон.
Мережеві запити верифікації (challenge → assertion → approve; 2–4
запити залежно від того, чи вже зареєстрований App Attest-ключ)
несуть лише результати перевірок як enum, а не дані документа:

```json
POST /auth/verify/approve   // тіло — канонічний payload, підписаний App Attest
{
  "method": "nfc_passport",
  "passiveAuthentication": "not_performed",
  "liveness": "heuristic",
  "faceMatch": "passed",
  "faceModel": "coreml",
  "protocolVersion": 2,
  "challengeId": "…"
}
```

Ні номера документа, ні імені, ні дати народження, ні фото. Сервер
зберігає `verified`, дату й метод (`docs/server-side.md`).

> **Чесно про рівень довіри.** Assertion App Attest тепер ПРИВʼЯЗАНИЙ
> до цього payload (hash = challenge ‖ canonicalPayload), а сервер
> перевіряє assertion counter (replay). Але поки
> `passiveAuthentication` != `passed`, сервер НЕ має криптодоказу
> справжності чипа — це «базовий», а не «сильний» Verified ID.
> Див. `docs/threat-model.md`.

## Як працює перевірка (усе — на пристрої)

1. **MRZ** (`Sources/Verification/MRZ`) — сканування машинозчитуваної
   зони камерою (Vision) або ручний ввід. Номер документа, дата
   народження і термін дії використовуються ЛИШЕ як ключ доступу
   BAC/PACE до NFC-чипа — так влаштований стандарт ICAO 9303.
2. **NFC** (`Sources/Verification/NFC`) — читання чипа
   ([NFCPassportReader](https://github.com/AndyQ/NFCPassportReader)):
   DG1 (дані документа) і DG2 (фото власника). Обидва живуть тільки
   в оперативній памʼяті процесу. Тут же — перевірка, що документ
   виданий Україною.
3. **Face check** (`Sources/Verification/Camera`) — звірка обличчя
   з фото з чипа: FaceNet (CoreML) рахує ембеддинги локально.
   Ніщо з цього не передається і не зберігається.
   > **Обмеження (у планах).** Поточна «liveness» — евристика
   > (стабільне обличчя в кадрі 12 послідовних кадрів), а НЕ повний
   > presentation-attack detection. Захист від фото/відео/маски
   > потребує TrueDepth/активних дій — заплановано. README раніше
   > переоцінював це як «depth/LiDAR» — виправлено.
4. **Підтвердження** (`Sources/Attestation`) — App Attest доводить
   серверу, що запит іде зі справжнього застосунку на справжньому
   iPhone (обійти перевірку скриптом не можна), після чого сервер
   ставить прапорець Verified ID.

## Що НЕ відбувається

- Дані документа не пишуться на диск, в UserDefaults чи Keychain.
- Дані документа не логуються.
- Фото з чипа і ембеддинги обличчя не завантажуються нікуди.
- Імʼя в профілі — нік користувача, не паспортне імʼя.

Перевірити це можна пошуком по цьому репозиторію: жодного
`URLRequest`/`UserDefaults`/`FileManager` з паспортними полями немає.

## Структура

```
Sources/Verification/   — кроки перевірки: MRZ → NFC → face check
Sources/Attestation/    — App Attest + єдиний запит approve
docs/server-side.md     — серверний обробник: що саме пишеться в базу
```

Код публікується як довідковий зріз робочого модуля (залежить від
внутрішніх компонентів застосунку, тому не збирається окремо).

## Ліцензія

MIT — див. [LICENSE](LICENSE). Питання і аудит: issues цього репозиторію
або borodkin0311@gmail.com.

---

# OstrovUA — Verification module (English)

Open source of the identity-verification module of **OstrovUA**.
Published so anyone can audit one claim: **passport data is never
collected and never leaves the phone.**

The only network call after a successful check is
`POST /auth/verify/approve` with `{ "method", "challengeId" }` —
no document fields. The server stores `verified: true`, a timestamp
and the method string, nothing else (see `docs/server-side.md`).

MRZ is used solely as the ICAO 9303 BAC/PACE access key to the NFC
chip; DG1/DG2 chip data and face embeddings live in process memory
only — no disk writes, no logs, no uploads. App Attest proves the
request comes from a genuine app on a genuine device.
