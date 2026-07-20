# Відповідь на повний аудит від 2026-07-19 (snapshot b403f8e)

Дякуємо за глибокий аудит і робочі PoC. Важливий контекст: аудит
виконано по snapshot **b403f8e** — коміт **4efc761** (CSCA pinning,
TrueDepth depth liveness, уточнена threat-model) на момент аудиту
вже існував, але не потрапив в архів. Частина Critical-знахідок
адресована саме ним. Нижче — статус КОЖНОЇ знахідки. Ми свідомо
розділяємо «виправлено кодом», «частково», «прийнято як roadmap»
і не називаємо зробленим те, що не зроблено.

## Critical

**P0-01 (masterlist poisoning) — ВИПРАВЛЕНО (4efc761 + поточний коміт).**
PoC відтворювався на версії скрипта без пінів. Зараз:
`pins_ua.txt` — SHA-256 відбитки довірених UA CSCA (у git); незапінений
сертифікат НЕ потрапляє в корінь довіри (у PoC: «ПРОПУЩЕНО», exit 1 —
жодного UA-сертифіката в довірі). `pins_ml_signer.txt` — відбиток
підписанта BSI; невідповідність = СТОП до ручної перевірки. Первинна
фіксація звірена за двома незалежними джерелами (BSI ↔ знімок ICAO PKD,
`Server/crosscheck_icao.sh`): 3 корені підтверджені обома, 2 (2024)
поки лише BSI. Залишок чесно відкритий: TOFU-вікно першого запуску,
rollback/freshness-контроль (P1-11) — roadmap.

**P0-02 (basic-видача Verified ID) — ВИПРАВЛЕНО (поточний коміт).**
Режим `PA_ENFORCE` видалено. PA обовʼязкова беззастережно:
`pa.status !== 'passed'` → 400/503, verified НЕ ставиться. `sod` і
`dgHashes` — обовʼязкові поля схеми. Таблиця «PA_ENFORCE=false →
verified basic» з evidence.txt більше не відповідає коду.

**P0-03 (liveness = face presence) — ЧАСТКОВО (4efc761), чесно.**
На пристроях з TrueDepth кожен зарахований кадр перевіряється мапою
глибини (least-squares площина, RMS-залишок ≥5 мм; фото/екран ~1–2 мм
навіть з нахилом/вигином). Сервер отримує чесний режим
`liveness: depth|heuristic`; `strong` рівень — лише при `depth`
(`heuristic` → `standard`, окрема позначка в базі). ПОГОДЖУЄМОСЬ:
це не measured PAD (ISO 30107-3): маска/зліпок не покриті,
challenge-response відсутній, attack evaluation не проводилась —
умова production-релізу, не «зроблено».

**P0-04 (face model provenance) — ЧАСТКОВО, решта — умова релізу.**
Опубліковано `Provenance/MODEL.md`: SHA-256 моделі, походження
(FaceNet, скрипт конвертації), спосіб перевірки. ВІДКРИТО (чесно):
іменований output tensor, preprocessing contract, калібрування
порогів, незалежна біометрична оцінка FAR/FRR. Без цього ми самі
не заявляємо production-готовність біометрії.

**P0-05 (evidence protocol / слабкий серверний verifier) — ВИПРАВЛЕНО
кодом у частині схеми; межа чесно зафіксована.**
Сервер тепер: строгий whitelist `method`, `protocolVersion === 3`,
`endpoint`, `faceMatch === 'passed'`, `faceModel === 'coreml'`,
`liveness ∈ {depth, heuristic}`, обовʼязкові `sod`+`dgHashes` (форма
перевіряється). App Attest verifier (`Server/appattest.js`) —
опубліковано повністю. ФОРМУЛЮВАННЯ ПРИЙНЯТО: PA доводить
справжність підписаного LDS, а НЕ виконання сенсорного flow —
саме так це тепер сформульовано в threat-model (розділи A/B:
доказ неможливості server-side підтвердження читання DG без
передачі персональних даних).

**P0-06 (reproducibility) — ЧАСТКОВО, решта — план.**
Опубліковано: `Server/passiveauth.js` + `Server/appattest.js`
(повний серверний verifier), `Provenance/Package.resolved`
(закріплені версії залежностей), `Provenance/MODEL.md` (hash моделі).
ВІДКРИТО: reproducible build, tests/CI, entitlements/Privacy
Manifest, повний network layer. Погоджуємось, що без цього репозиторій
— «illustrative snapshot», і саме так він і позиціонується.

## High

**P1-01 (CRL/час) — ЧАСТКОВО.** `PA_NO_CHECK_TIME` тепер діє ЛИШЕ
поза production (guard по `APP_ENV`). CRL-pipeline — roadmap.

**P1-02 (клони чипа) — відома межа, roadmap.** Chip/Active
Authentication — наступна віха; NFCPassportReader виконує CA
автоматично, план — пробросити результат у evidence і політику.

**P1-03 (SHA-224) — ВИПРАВЛЕНО.** Клієнт рахує sha1/224/256/384/512
(SHA-224 через CommonCrypto); LDS-парсер знає OID 2.16.840.1.101.3.4.2.4.
Тест аудиту тепер проходить.

**P1-04 (самописний DER) — ЧАСТКОВО.** Додано: повне споживання
буфера (root і 0x77), заборона дублікатів DG, валідація діапазону
номерів DG, відповідність довжини хешу алгоритму, заборона
неканонічних довжин. Погоджуємось: це не заміна зрілої ASN.1 —
fuzz/property-тести і повний ICAO-профіль у плані.

**P1-05 (event-loop blocking) — ВИПРАВЛЕНО.** Усі openssl-виклики
асинхронні (`execFile` + timeout + maxBuffer), fs — promises,
семафор на 2 конкурентні перевірки, ліміт розміру ДО декодування.

**P1-06 (client races) — ЧАСТКОВО.** Повторний запуск звірки
блокується, камера/NFC глушаться при зміні екрана. Formal state
machine / transaction id / Task cancellation — прийнято, roadmap
(разом із P2-01).

**P1-07 (AVFoundation lifecycle) — ПРИЙНЯТО, roadmap.** Разом з
P1-06 у рефакторинг координатора.

**P1-08 (MRZ) — ВИПРАВЛЕНО в заявленому обсязі.** Строгий алфавіт
`^[A-Z0-9<]{44}$`, чек-цифра optional data (поз. 42, з правилом
порожнього поля), валідація статі M/F/<. Обидва кейси з harness
аудиту (illegal char, wrong optional check) тепер відхиляються.

**P1-09 (privacy overclaim) — ВИПРАВЛЕНО в доках.** README тепер
формулює точну обіцянку: «поля документа і фото не передаються»,
з явною згадкою, що SOD/хеші — унікальні для примірника артефакти.
Privacy overlay / retention review — roadmap.

**P1-10 (fraud controls) — ПРИЙНЯТО, roadmap.** Keyed-HMAC
дедуплікація «один документ = один акаунт» описана в threat-model
як privacy-зважене рішення; ліміти спроб — план.

**P1-11 (trust-list operations) — ПРИЙНЯТО, roadmap.** Поточний
стан: піни блокують підміну коренів; freshness/rollback/atomic
promotion — план операційного контуру.

## Medium

**P2-01 (архітектура View) — ПРИЙНЯТО, roadmap** (координатор/actor).
**P2-02 (dead code) — ВИПРАВЛЕНО:** `VerificationStep.swift`,
`PassportDataMatcher.swift`, `CameraDepthVerificationManager.swift`
видалені з застосунку і репозиторію (жодних зовнішніх посилань).
**P2-03 (typed DTO) — ПРИЙНЯТО, roadmap.**
**P2-04 (docs integrity) — ВИПРАВЛЕНО:** протокол у шапці
AppAttestService приведено до коду (canonical payload, v3);
audit-checklist більше не згадує release-fallback; Package.resolved
реально лежить у `Provenance/`.
**P2-05 (App Attest key lifecycle) — ПРИЙНЯТО, roadmap.**
**P2-06 (face preprocessing) — ПРИЙНЯТО, roadmap** (разом з P0-04).
**P2-07 (error taxonomy) — ПРИЙНЯТО, roadmap.**

## Підсумок

Виправлено кодом зараз: P0-01, P0-02, P0-05 (схема+verifier),
P1-03, P1-05, P1-08, P2-02, P2-04; частково: P0-03, P0-04, P0-06,
P1-01, P1-04, P1-06, P1-09. Прийнято як умови релізу (НЕ заявляємо
зробленим): measured PAD, біометрична оцінка моделі, Chip/Active
Authentication, CRL, reproducible build + тести, state machine,
fraud controls, trust-list ops.

Вердикт NO-GO щодо production identity system ми не оскаржуємо —
до закриття умов вище. Оскаржуємо лише дві позиції фактично:
(1) trust bootstrap 0/10 — виправлено пінами до дати аудиту
(коміт 4efc761 не потрапив у snapshot); (2) «PA_ENFORCE=false →
verified basic» — видалено. Просимо повторний прогін обох PoC
на HEAD.
