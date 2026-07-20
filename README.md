# OstrovUA — модуль верифікації (Verified ID)

Відкритий вихідний код модуля верифікації застосунку **OstrovUA** —
спільноти українців із підтвердженням особи за біометричним паспортом.

Публікуємо цей код, щоб кожен міг перевірити ТОЧНУ обіцянку:
**поля документа (імʼя, номер, дата народження) і фото не
передаються на сервер і не зберігаються.** На сервер ідуть лише
криптографічні артефакти — EF.SOD (державні підписи й хеші, без
персональних полів) та хеші груп даних. Хеші унікальні для
примірника документа — це чесно задокументовано в threat-model.

## Головна гарантія приватності

Персональні поля документа НЕ передаються на сервер: ані номер, ані
імʼя, ані дата народження, ані фото. Мережеві запити верифікації
(challenge → assertion → approve) несуть результати перевірок і
криптографічні артефакти — не дані людини:

```json
POST /auth/verify/approve   // тіло — канонічний payload, підписаний App Attest
{
  "method": "nfc_passport",
  "liveness": "heuristic",
  "faceMatch": "passed",
  "faceModel": "coreml",
  "sod": "<EF.SOD, base64>",
  "dgHashes": { "dg1": { "sha256": "…" }, "dg2": { "sha256": "…" } },
  "protocolVersion": 3,
  "challengeId": "…"
}
```

**Що таке `sod` і чому це не «паспортні дані».** EF.SOD — обʼєкт
безпеки чипа (ICAO 9303): хеші груп даних + сертифікат Document
Signer + підпис держави. У ньому НЕМАЄ жодного персонального поля.
Сервер перевіряє за ним справжність документа (Passive
Authentication: підпис → DSC → CSCA України) і одразу видаляє;
у базі лишається тільки `verified`, дата й метод
(`docs/server-side.md`, `Server/passiveauth.js`).

> **Чесна межа.** Хеші в SOD унікальні для конкретного документа —
> дані з них відновити не можна, але це технічний ідентифікатор
> примірника. З нього сервер рахує і зберігає ОДНОСТОРОННІЙ токен
> `HMAC(pepper, хеш DG1)` — виключно щоб один паспорт не міг
> верифікувати кілька акаунтів і щоб бан документа був незворотним.
> Відновити з токена номер/імʼя неможливо (pepper — поза базою).
> І друге: PA доводить справжність ДАНИХ чипа, але не ловить точну
> копію чипа (клон) — для цього існує Chip/Active Authentication,
> це наступний етап (`docs/threat-model.md`).

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
   Liveness: на пристроях з TrueDepth кожен зарахований кадр
   перевіряється мапою глибини (площина-фіт: фото/екран = відмова);
   без TrueDepth — чесний режим `heuristic`, сервер це бачить.
   > **Обмеження.** Це реальний захист від фото і відео з екрана,
   > але НЕ сертифікований PAD (ISO 30107-3): обʼємна маска —
   > окремий трек. Див. threat-model.md.
4. **Підтвердження** (`Sources/Attestation` + `Server/`) — два
   незалежні докази:
   - **App Attest**: запит іде зі справжнього, незміненого застосунку
     на справжньому iPhone; assertion підписує САМЕ цей payload.
   - **Passive Authentication (сервер)**: підпис держави над даними
     чипа перевіряється за CSCA України (`Server/passiveauth.js`).
     Битий/підроблений SOD або розбіжність хешів DG — відмова.
   Лише після цього сервер ставить прапорець Verified ID.

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
Sources/Attestation/    — App Attest + запит approve (канонічний payload)
Server/                 — Passive Authentication: passiveauth.js (дослівно
                          з продакшену) + скрипти CSCA masterlist
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

The approve request carries check results and cryptographic
artifacts only — no document fields: outcome enums, the chip's
EF.SOD (state-signed data-group hashes + certificate — no personal
fields) and DG1/DG2 hashes. The server performs ICAO 9303 Passive
Authentication against the Ukrainian CSCA masterlist
(`Server/passiveauth.js`), then discards the SOD; it stores
`verified: true`, a timestamp and the method string, nothing else
(see `docs/server-side.md`).

MRZ is used solely as the ICAO 9303 BAC/PACE access key to the NFC
chip; DG1/DG2 chip data and face embeddings live in process memory
only — no disk writes, no logs, no uploads. App Attest proves the
request comes from a genuine app on a genuine device and binds the
assertion to this exact payload. Known limit (documented in
`docs/threat-model.md`): PA proves data authenticity, not chip
uniqueness — clone detection (Chip/Active Authentication) is the
next milestone.
