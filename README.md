# OstrovUA — модуль Verified ID

Відкритий код перевірки особи OstrovUA за українським біометричним
документом. Репозиторій дає змогу перевірити реалізацію, межі довіри та
політику мінімізації даних.

## Точна гарантія приватності

У protocol v7 застосунок шифрує сирі DG1/DG2/DG14/DG15 з NFC-чипа, виділене
фото DG2, AA transcript та короткі JPEG-кадри перевірки живої присутності
одноразовим X25519 +
HKDF-SHA256 + AES-256-GCM ключем, привʼязаним до серверного challenge. Через
TLS на **власний сервер OstrovUA** надходить ciphertext. Довгоживучий auth
бачить і журналює лише непрозорий envelope; розшифрувати його може тільки
ізольований biometric worker. Це дає серверу змогу незалежно повторити
Passive Authentication, face-match і PAD, не довіряючи результату телефона.

Для server-owned Chip Authentication auth-сервіс додатково отримує DG14
через TLS до завершення NFC-сеансу. DG14 містить публічні CA
параметри/ключ чипа, а не MRZ, імʼя, номер документа чи фото. Auth незалежно
парсить DG14, тримає ephemeral private key лише всередині короткоживучого
AES-GCM token, перевіряє один protected GET CHALLENGE і затирає request
buffers. У БД записується тільки одноразова квитанція з SHA-256 DG14 та
неперсональними protocol identifiers; raw DG14 і APDU не зберігаються.

Ці матеріали:

- не передаються сторонньому біометричному провайдеру;
- не записуються у PostgreSQL, object storage, файли, access/error logs або
  аналітику;
- обробляються в ізольованому self-hosted worker-процесі, який приймає рівно
  один запит і завершується після відповіді;
- plaintext існує лише в address space одноразового worker, не в auth;
- декодовані буфери затираються перед звільненням, core dump і swap вимкнені,
  root filesystem контейнера read-only;
- видаляються з памʼяті разом з address space завершеного worker-процесу.

Довготривало зберігаються лише статус Verified ID, односторонній
`HMAC(pepper, signed DG1 hash)` для правила «один документ — один акаунт» і
мінімальна підписана технічна квитанція: версія політики, хеш набору моделей,
час, результат і document assurance. MRZ, номер документа, імʼя, дата
народження, DG1/DG2/DG14/DG15, фото, кадри, embeddings та біометричні scores
у квитанції відсутні.

> Чесна технічна межа: Swift і Python мають керовану памʼять, тому
> неможливо математично довести перезапис кожної внутрішньої immutable-копії.
> Гарантія реалізована сильнішою процесною межею: один запит — один процес,
> після чого ОС знищує весь його address space. Для аудиту потрібні також
> перевірка production-конфігурації та журналів, а не лише вихідного коду.

## Серверне рішення v7

`POST /auth/verify/approve` послідовно:

1. перевіряє JWT та Apple App Attest над точними байтами payload;
2. споживає окремі одноразові challenge для active liveness та document auth;
3. передає application-encrypted envelope тільки внутрішньому одноразовому
   worker, який розшифровує його і сам обчислює хеші DG1/DG2/DG14/DG15;
4. звіряє worker-хеші з App-Attest-підписаними хешами та EF.SOD, перевіряє
   CMS-підпис, DSC → CSCA chain і доступний CRL;
5. у тому самому worker перевіряє DG15 Active Authentication, а auth-сервіс
   незалежно перевіряє server-owned DG14 CA secure-messaging transcript;
6. перевіряє DG2-face ↔ live-face, passive PAD та nonce-derived active
   challenge;
7. однією транзакцією перевіряє ban/duplicate і споживає CA-квитанцію;
   лише server-verified AA або server-owned CA може активувати Verified ID
   після calibration gate, решта спрямовується у review.

Невідомі поля, replay/downgrade, розбіжність DG, відсутній trust material,
непройдений PAD/face-match, невалідна квитанція або недоступність сервісу
завершуються відмовою. Protocol v6 та старі envelope contracts відхиляються.

## Калібрування перед увімкненням

Автоматичне рішення fail-closed, доки незалежний physical holdout не пройде
вимоги FMR/FNMR/APCER/BPCER для print/screen/mask/injection/deepfake. Дозвіл
привʼязаний одночасно до SHA-256 звіту, його Ed25519-підпису, точного хешу
моделей і версії політики. Самовільна зміна прапорця без відповідного
read-only звіту не активує worker.

Код і документи:

- `Server/server.js` — єдиний актуальний серверний orchestration;
- `Server/document_ca.js` — незалежний DG14/ECDH/AES transcript verifier;
- `Server/passiveauth.js` — ICAO 9303 Passive Authentication;
- `Server/biometric_service/` — isolated face-match/PAD worker та evaluator;
- `Server/migrations/20260724_document_assurance_v7.sql` — атомарна
  активація/review з явним document assurance;
- `Server/migrations/20260725_server_owned_ca.sql` — одноразові CA receipts
  та атомарне споживання під час активації;
- `docs/server-side.md` — контракт і production gates;
- `docs/threat-model.md` — загрози та відомі межі.

Каталог `Sources/` зберігає історичний reference client для аудиту. Production
v7 iOS-клієнт є частиною основного репозиторію застосунку; сервер не дозволяє
legacy challenge або payload compatibility.

## Ліцензія

MIT — див. [LICENSE](LICENSE). Питання та аудит: GitHub Issues.

---

# OstrovUA — Verified ID module

Open-source implementation of OstrovUA identity verification for Ukrainian
biometric documents.

## Exact privacy claim

In protocol v7, the app encrypts raw NFC DG1/DG2/DG14/DG15, the extracted
DG2 portrait, the AA transcript and short liveness JPEG frames with X25519 +
HKDF-SHA256 + AES-256-GCM bound to one-time server challenges. Only ciphertext
of biometric and biographic evidence is sent over TLS to **OstrovUA's own
server**. The long-lived auth process
cannot decrypt it; only the isolated one-request biometric worker holds the
private key and plaintext. This lets the server independently repeat Passive
Authentication, Active Authentication, face matching and PAD instead of
trusting client-declared results.

Server-owned Chip Authentication has one explicit exception to the
ciphertext-only evidence path: DG14 is sent to auth over TLS while the NFC
session is still open. DG14 contains public CA parameters and the chip public
key, not MRZ, document fields or the portrait. Auth independently parses DG14,
keeps its ephemeral private key only inside a short-lived AES-GCM token,
verifies exactly one protected GET CHALLENGE, and clears request buffers. The
database stores only a single-use receipt containing the DG14 digest and
non-personal protocol identifiers; raw DG14, APDUs and session keys are not
persisted.

The evidence is not sent to a third-party biometric provider and is not
persisted in PostgreSQL, object storage, files, logs or analytics. It is
processed by an isolated one-request worker with a read-only filesystem, no
swap, no core dumps and no public network. Decoded buffers are overwritten and
the worker exits after the response, causing the OS to destroy its complete
address space.

Persistent state is limited to Verified status, a one-way peppered document
token used to prevent duplicate accounts, and a signed technical receipt
containing policy/model hashes, time and outcome. MRZ, document fields,
DG1/DG2/DG14/DG15, images, frames, embeddings and biometric scores are not
stored.

Managed Swift/Python runtimes cannot honestly prove that every internal
immutable copy was overwritten. The enforceable memory boundary is therefore
one request per process and OS destruction of that process, combined with
production configuration and log audits.

Protocol v7 activates Verified ID atomically only after App Attest, one-time
liveness/document challenges, server-side SOD and AA verification,
self-hosted PAD and face match all pass. Client-reported or merely
App-Attest-bound CA status remains review-only. A server-owned CA transcript
is independently verified through ECDH/AES secure messaging and consumed as a
one-time receipt bound to the App Attest key, document challenge and DG14
digest. Documents without server-verified AA or server-owned CA remain
review-only. Automatic approval stays
fail-closed until an independent physical holdout report satisfies the pinned
FMR/FNMR/APCER/BPCER policy and matches the exact model-set and policy hashes.

See `docs/server-side.md`, `docs/threat-model.md` and
`Server/biometric_service/README.md` for the auditable contract.
The `Sources/` directory is a historical reference; the production v7 iOS
client is maintained with the main application.
