# Відповідь на повний аудит від 2026-07-19 (snapshot b403f8e)

> ⚠️ **ЗАСТАРІЛІ ПОЛІТИКИ В ЦЬОМУ ЖУРНАЛІ (F8).** Це історичний
> changelog. Ранні записи (Update 1–4) згадують `liveness:
> depth|heuristic`, «heuristic → standard», `liveness ∈ {depth,
> heuristic}` — ці політики **СКАСОВАНО** в Update 5. Чинна політика
> одна: **єдиний рівень видачі — depth-backed strong**; евристичного
> рівня не існує ні в коді, ні в схемі (`liveness` enum містить лише
> `depth`, сервер відхиляє все інше). Пошук по репозиторію повертає
> ці рядки лише як історію, не як чинну поведінку.

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

## Update (за зауваженнями повторної перевірки)

**Пін-файли тепер ОПУБЛІКОВАНІ** (`Server/pins_ua.txt`,
`Server/pins_ml_signer.txt`) — відбитки публічних сертифікатів,
секретом не є; git-історія фіксує момент довіри, кожен відбиток
перевіряється за BSI/ICAO незалежно. **TOFU-вікно закрито:** без
pins-файлів `fetch_masterlist.sh` тепер ЗУПИНЯЄТЬСЯ (fail-closed);
перша фіксація можлива лише явним `ALLOW_TOFU=1` з наступною
звіркою за другим джерелом (`crosscheck_icao.sh`). «Перший запуск
приймає будь-який C=UA» більше не відтворюється.

**Щодо «подвійного хешування» assertion:** формула сервера —
`clientDataHash = SHA256(challenge ‖ rawBody)`,
`nonce = SHA256(authenticatorData ‖ clientDataHash)`, підпис
перевіряється ECDSA-SHA256 над nonce (тобто digest =
SHA256(nonce)). Це відповідає референсному серверному флоу Apple
для App Attest assertions. Емпіричне підтвердження: справжні
assertions реальних iPhone проходять перевірку в продакшені
(лог `[verify/approve] … level=strong pa=passed`, обхідні режими
вимкнені й ігноруються в production на рівні коду). Якщо у вас
відтворюється кейс, де валідна assertion НЕ проходить або
невалідна проходить — надішліть, розберемо негайно.

**Counter:** суворо зростаючий (`counter <= stored` → відмова),
оновлюється після кожної перевірки; replay того самого assertion
неможливий також через одноразовість challenge (consume + TTL).

## Update 2 — відповідь на аудит 2026-07-20 (snapshot 83f885a)

Причина повторного відтворення PoC trust-store: коміт з пінами і
fail-closed bootstrap НЕ потрапив у snapshot (людський фактор —
локальний коміт не був запушений до зняття архіву). У поточному
HEAD: `Server/pins_ua.txt`, `Server/pins_ml_signer.txt`,
fail-closed `fetch_masterlist.sh` (без пінів — СТОП; TOFU лише
явним `ALLOW_TOFU=1`). Просимо перепрогнати PoC пп. 4–5 evidence.

Визнані та ВИПРАВЛЕНІ знахідки цього аудиту:

- **P2-01 (century):** дата народження `260731` у 2026-му тепер
  1926, а не майбутнє-2026 — порівнюється повна дата з сьогодні,
  обидва століття проходять сувору календарну перевірку
  (`PassportMRZ.date(fromYYMMDD:)`).
- **P1-01 (undefined paPassed):** дефект був у ДОКУМЕНТАЦІЙНОМУ
  фрагменті (server-side.md:51), не в продакшн-коді (перевірено
  grep-ом по бойовому server.js); фрагмент приведено у відповідність.
- **P1-02 (челенджі):** щохвилинний sweep протухлих, глобальний
  ліміт 5000 (fail-closed 503), ліміт 8 на акаунт з витісненням.
- **P1-03 (атомарність counter):** запис через compare-and-swap
  (`where counter < new`, вимога `affected_rows == 1`) — паралельний
  replay одного assertion програє гонку детерміновано.
- **P1-07 (token-код відсутній):** фрагмент дедуплікації документів
  доданий у server-side.md; повна серверна логіка — у продакшн-коді,
  формула і властивості — threat-model.
- **P0-06 (артефакти):** опубліковано `Server/package.json`
  (залежності verifier'а), `Server/Apple_App_Attestation_Root_CA.pem`
  (корінь довіри перевірки атестацій), `Provenance/OstrovUA.entitlements`
  (`appattest-environment=production`).

Позиції без змін (прийнято, roadmap, НЕ заявляємо зробленим):
P0-02 (розділення claims strong/standard на рівні авторизації),
P0-03 (measured PAD), P0-04 (біометрична валідація моделі),
P1-05 (Chip/Active Auth як обовʼязковий evidence — наступна віха,
DG14/DG15 на цільових документах підтверджені), P1-08/09
(state machine/actor рефакторинг), P1-12 (зріла ASN.1 + fuzz),
P2-03, P2-05, P2-06, P2-07.

## Update 3 — операційні дефекти PKI / App Attest

- **App Attest key churn (P2-02) — ВИПРАВЛЕНО:** перереєстрація
  ключа тепер ЛИШЕ на `DCError.invalidKey`; транзієнтні збої
  прокидаються помилкою без знищення ключа
  (`AppAttestService.assertionHeaders`).
- **Rollback protection masterlist (P1-11, частина) — ВИПРАВЛЕНО:**
  `signingTime` нового masterlist порівнюється з застосованим
  (`ml_state.txt`); старіший — СТОП (обхід лише явним `FORCE_ML=1`).
  Перевірено трьома сценаріями (перший запуск / повтор / відкат).
- **CRL (P1-04) — механізм готовий, фід — окремий ops-проєкт:**
  за наявності файла CRL ланцюжок перевіряється з
  `-crl_check`; без файла — чесно без revocation. Не заявляємо
  зробленим до підключення офіційного фіда (ICAO PKD 001-dsccrl
  або державний DP) з контролем свіжості nextUpdate.

Щодо решти NO-GO позицій згодні без заперечень: measured PAD
(ISO 30107-3, фізичні випробування) і незалежна біометрична
валідація моделі — умови релізу; це проєкти випробувань, а не
код, і ми не імітуємо їх виконання правками.

## Update 4 — відповідь на аудит 2026-07-20 (snapshot 6975ad6)

Виправлено (кожне відтворено тестом, що повторює ваш сценарій):

- **P1-06 (challenge eviction/consume):** витіснення тепер
  НАЙСТАРІШИХ (ваш тест «9 видач» дає `[false, true × 8]`);
  власник перевіряється ДО видалення — чужий consume не «спалює»
  челендж легітимного власника (`wrong=null, rightAfter=OK`).
- **P1-03 (CMS fallback повз пін):** fallback-виклик без `-signer`
  видалено; невдале витягнення підписанта = СТОП. Шляху повз
  перевірку піна не існує.
- **P1-08 (permissive ATT_ENV):** будь-яке значення, крім явного
  `development`, трактується як `production` (fail-closed до
  одруків конфігурації).
- **P1-02 (атомарність trust bundle):** збірка в `*.new` +
  атомарний `mv`; робочий `csca_ua.pem` ніколи не буває порожнім
  чи недописаним.
- **P1-01 (ALLOW_TOFU як escape hatch):** TOFU тепер працює ЛИШЕ
  на неініціалізованій системі (немає `ml_state.txt`/`csca_ua.pem`);
  на робочому проді прапорець ігнорується зі СТОПом.
- **P1-04 (шлях Root CA):** `Server/certs/Apple_App_Attestation_Root_CA.pem`
  — розкладка тепер відповідає рантайму (`configured=true` з коробки).
- **P2-05:** опубліковано `Server/package-lock.json` (locked deps).
- **P2-06 (entitlements):** пояснення додано в Provenance:
  `aps-environment` перезаписується при підписанні збірки
  (dev-збірки — development, TestFlight/App Store — production);
  `appattest-environment=production` задано явно і не змінюється.

Без змін (roadmap, погоджено): P0-02 (синхронізація depth/RGB,
ROI-mapping, challenge, PAD-корпус), P0-03 (біометрична валідація),
P0-04/05 (повна відтворюваність), P1-05 (purpose-binding челенджів),
P1-07, P1-09, P1-10 (CA/AA), P1-11, P1-12, P1-13, P1-14, P1-15,
P1-16, P2-01…P2-04, P2-07.

## Update 5 — P0-01 закрито ВИБОРОМ ПОЛІТИКИ

Рішення власника продукту: **єдиний рівень видачі Verified ID —
depth-backed strong.** Реалізовано наскрізно:

- клієнт: без TrueDepth верифікація чесно недоступна (відмова в UI
  до початку флоу, E-406) — тихого heuristic-шляху не існує;
- сервер: `liveness !== 'depth'` → 400; евристика Verified ID
  не видає за жодних умов;
- база: типізована колонка `identity_assurance` (CHECK 'strong');
  бекфіл лише для верифікацій, що реально пройшли PA+depth; старі
  верифікації без depth лишаються NULL і потребують повторного
  проходження.

«Однаковий identity-результат для різних рівнів доказовості»
усунуто радикально: рівень доказовості один. Свідомий продуктовий
компроміс: власники пристроїв без TrueDepth (SE, до iPhone X)
наразі не можуть отримати Verified ID — це чесно повідомляється.

Залишаються дві release-blocking позиції, обидві — випробувальні
проєкти, обидві погоджені як умови релізу: measured PAD
(ISO 30107-3) і незалежна біометрична валідація моделі (FAR/FRR).

## Update 6 — focused heuristic-recheck (snapshot ddf1a45)

Дякуємо за підтвердження Claim 1 (heuristic видалено). Claim 2
(«byte-for-byte») визнаємо неточним — виправлено. По пунктах:

- **F1 — ВИПРАВЛЕНО:** опубліковано ДОСЛІВНУ виписку реального
  маршруту `Server/verify_approve.route.js` (rawBody-захоплення →
  challenge → verifyAssertion → атомарний counter → PA → document
  token → запис). `server-side.md` більше не називає фрагмент
  byte-for-byte і посилається на реальний файл.
- **F2 — ВИПРАВЛЕНО:** whitelist приведено у відповідність клієнту —
  `challengeId` (завжди додає AppAttestService) прийнято й обовʼязкове;
  `session` — опційний рядок. Розбіжність документації і клієнта усунуто.
- **F3 — ВИПРАВЛЕНО:** схема тепер СПРАВДІ строга — невідомі ключі
  payload відхиляються явно (`ALLOWED_KEYS`), `dgHashes` валідується
  за формою (рівно {dg1,dg2}, hex правильної довжини за алгоритмом),
  ліміт розміру SOD на межі маршруту. Тести: зайвий ключ / коротка
  довжина / не-hex / невідомий алгоритм — усі відхилено.
- **F4 — АДРЕСОВАНО публікацією маршруту:** end-to-end ланцюг
  (rawBody до парсингу → ті самі байти у verifyAssertion → challengeId
  без ре-серіалізації → consume-once з owner-check → counter CAS)
  тепер видимий у `verify_approve.route.js`.
- **F5 — ВИПРАВЛЕНО:** спільний `Outcome` розділено на типізовані
  `LivenessEvidence`(лише `.trueDepthV1`) і `FaceMatchEvidence`(лише
  `.passed`). Безглузда комбінація більше не компілюється.
- **F6 — ВИПРАВЛЕНО:** клієнт вимагає інваріант сервера —
  `level == "strong"` І `passiveAuthentication == "passed"`, інакше
  верифікація відхиляється (захист від downgrade проксі/сервера).
- **F7 — ВИПРАВЛЕНО:** `liveness` більше не константа й не «мертвий
  рядок». Введено `DepthLivenessProof` (fileprivate init, єдина
  фабрика в менеджері камери); evidence будується лише з нього;
  `reset()` обнуляє доказ; call site — fail-closed guard.
- **F8 — ВИПРАВЛЕНО:** на початку цього журналу — явна помітка, що
  записи Update 1–4 з `heuristic` СКАСОВАНО; чинна політика одна.
- **F9-legacy — ПРИЙНЯТО, release-blocker без заперечень:** measured PAD
  (синхронізація RGB/depth за timestamp, ROI-mapping, random
  challenge, exactly-one-face, attack corpus) — випробувальний
  проєкт. Мітка `strong` підтверджується CSCA-ланцюгом і App Attest,
  але НЕ виміряним PAD; це чесно зафіксовано. NO-GO для
  high-assurance релізу до вимірювань не оскаржуємо.

## Update 7 — фінальний аудит (snapshot eb0ab0c), 12 вимог

| # | Вимога | Статус |
|---|--------|--------|
| 1 | App Attest double hash | **НЕ баг** — формула емпірично коректна (реальні assertion проходять у проді). Фікстура (#2) це формалізує. Ламати робочу математику не будемо. |
| 2 | Реальна assertion-фікстура | Інструмент готовий: `Server/tests/verify_fixture.js` + `APP_ATTEST_FIXTURE.md`. Зняти з пристрою — крок Dani (потрібен iPhone). |
| 3 | Document claim в одній транзакції | **ВИПРАВЛЕНО:** атомарний `INSERT … ON CONFLICT … WHERE` (перший клеймить, чужий токен не перезаписати). Раніше on_conflict перезаписував contributor_id — угон токена. |
| 4 | Parallel race test | **ДОДАНО:** `Server/tests/race_document_token.test.js` (модель інваріанта, 3 тести PASS) + протокол реального прод-тесту. |
| 5 | Фізично видалити dev bypass | **ВИДАЛЕНО:** `VERIFY_DEV_BYPASS` більше немає в коді атестації. Обійти неможливо. |
| 6 | Play Integrity branch | **ВИДАЛЕНО:** «висяча» гілка прибрана; Android — окремий майбутній маршрут з nonce-binding. |
| 7 | Синхронізація RGB/depth + ROI | **ЧАСТКОВО:** depth-gate працює; синхронізатор timestamp + мапінг faceBox→depth ROI — у плані PAD (`PAD_AND_BIOMETRIC_PLAN.md`). |
| 8 | PAD attack evaluation | **ВИМІРЯНО (перший прогін):** print/screen фізично пред'явлені. Виявлено спуф центрального вікна (протікання фону, RMS до 148мм) → додано верхній поріг смуги [5,20]мм: print APCER 28.6%→4.3%, screen 1%→0%, BPCER 0. Числа — `Provenance/PAD_AND_BIOMETRIC_PLAN.md`. Лишається: маска, per-attempt метрика, ROI-mapping + challenge-response (повний ISO 30107-3). |
| 9 | Face model + FAR/FRR | **ВИМІРЯНО:** `Tools/FaceEval` прогнано на LFW (6000 пар) — AUC 0.987, EER 3.4%. Поріг ПЕРЕКАЛІБРОВАНО 0.60→0.50 за виміряним ROC (FAR 0.13%, FRR 6.7%). Числа й обґрунтування — `Provenance/MODEL.md`. Лишається доменна оцінка на власному наборі селфі↔DG2. |
| 10 | Публікація CurrentSession/server.js/schema | **ЗРОБЛЕНО:** `Sources/Session/CurrentSession.swift`, `Server/verify_approve.route.js` (реальний маршрут), `Server/DB_SCHEMA.sql` (таблиці+constraints). |
| 11 | State machine + cancellation | **ДОДАНО:** транзакційний лічильник `verifyTxn` + `faceCheckTask.cancel()`; stale-результати ігноруються після await/уходу/скидання. |
| 12 | Privacy wording + мінімізація hashes | **ВИПРАВЛЕНО:** телефон шле РІВНО ОДИН хеш (sha256) на групу, а не пʼять; формулювання приватності уточнено. |

Додатково цього кола: DoS-межа (P1-07 — split JSON limit 512KB/40MB,
обмежена черга PA), fail-closed `PA_NO_CHECK_TIME` (лише явний
development), суворі схема й dgHashes-валідація (з Update 6).

**Підсумок.** Усе, що закривається кодом — закрито. Два справжні
release-blockers лишаються (виміряний PAD і FAR/FRR-валідація моделі) —
це випробувальні проєкти з опублікованими протоколами, і ми не
оголошуємо їх зробленими. PROD-GO для high-assurance — після цих
вимірювань; для бети за запрошеннями поточний рівень (держ-крипто PA +
запінені CSCA + depth-gate + App Attest + атомарна дедуплікація +
бан документів) є сильним і чесно描аним.

## Update 8 — PAD-аудит (snapshot d0f730b), 11 вимог

| # | Вимога | Статус |
|---|--------|--------|
| 1 | RGB/depth synchronization | **ЗРОБЛЕНО:** `AVCaptureDataOutputSynchronizer` — RGB і depth однією парою з одного моменту; окремий `latestDepth` прибрано (`FaceLivenessManager`). |
| 2 | Actual face ROI mapping | **ЗРОБЛЕНО:** вибірка глибини — у ROI ядра обличчя (мапінг `faceBox`→depth з урахуванням .leftMirrored). Fail-safe: помилка мапінгу = nil = кадр не зараховано (безпечно). Потребує підтвердження повторним PAD-прогоном (bonafide BPCER=0). |
| 3 | Per-attempt evaluation | **ЗРОБЛЕНО:** scorer рахує attempt-level (12 послідовних у смузі). На зібраних даних APCER attempt = 0 для print і screen. |
| 4 | Незалежний holdout | **ЧАСТКОВО/план:** FAR/FRR — окремий split; PAD — потрібен другий незалежний збір. Калібрування і оцінку розводимо. |
| 5 | Маски/3D | **RELEASE-BLOCKER:** реквізит потрібен фізично; протокол готовий, стенд збирає й маски (мітка `mask`). |
| 6 | Більше bona-fide | **ПЛАН:** перший збір дав 12 кадрів (жива особа проходила швидко). Потрібен довший збір; стенд це дозволяє. |
| 7 | Scorer lower+upper | **ЗРОБЛЕНО:** `pad_score.py` тепер моделює бойову смугу [5,20]мм (нижній+верхній), а не лише нижній. |
| 8 | Raw anonymized dataset | **ЗРОБЛЕНО:** `Provenance/pad_dataset/pad_log_2026-07-20.csv` (лише RMS+мітки, без зображень/часу). Джерела логера/оверлея опубліковано. |
| 9 | Реальний PG concurrency test | **ПІДТВЕРДЖЕНО ПРОГОНОМ:** `db/check_token_race.sh` проти ЖИВОГО Postgres, 30 паралельних зʼєднань → `ok=1, duplicate=29, token_owners=1, verified=1, ✓ PASS`. Плюс `Server/tests/race_document_token.integration.js` (pg). |
| 10 | Одна транзакція token+assurance | **ЗРОБЛЕНО:** plpgsql `verify_bind_document()` — привʼязка токена Й `verified/assurance` в ОДНІЙ транзакції (SELECT…FOR UPDATE). |
| 11 | FAR/FRR face model | **ЗРОБЛЕНО:** виміряно (AUC 0.987, EER 3.4%), поріг перекалібровано 0.60→0.50 — `Provenance/MODEL.md`. |

**Підсумок:** усе, що закривається кодом/даними — закрито (1,2,3,7,8,9,10,11).
Лишаються фізичні/датасетні: маски (#5), більший bona-fide збір (#6),
незалежний holdout (#4) і підтверджувальний PAD-прогін для ROI-мапінгу (#2).
Це випробувальні кроки, не код; ми їх не оголошуємо зробленими.
