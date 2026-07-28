# Серверний контракт Verified ID — protocol v7

Джерела істини:

- [`verify_approve.route.js`](../Server/verify_approve.route.js);
- [`passiveauth.js`](../Server/passiveauth.js);
- [`verification_policy.js`](../Server/verification_policy.js);
- [`self_hosted_contract.js`](../Server/self_hosted_contract.js);
- [`biometric_service`](../Server/biometric_service/);
- міграції
  [`20260724_document_assurance_v7.sql`](../Server/migrations/20260724_document_assurance_v7.sql)
  і
  [`20260724_verification_rate_limit_fail_closed.sql`](../Server/migrations/20260724_verification_rate_limit_fail_closed.sql).

Protocol v6 та envelope v1/v2 більше не є production-сумісними. Історичні
записи БД можуть залишатися для аудиту, але жоден HTTP route не приймає
старий challenge, payload або envelope.

## Послідовність рішення

1. iOS реєструє App Attest key до початку NFC.
2. Сервер видає два різні одноразові nonce: `document_auth` і `liveness`.
   Persistent limiter перевіряє account + App-Attest device. Втрата
   PostgreSQL або неповна limiter identity дає `503`, а не fallback.
3. NFC читає COM, SOD, DG1, DG2, а також DG14/DG15, якщо вони є.
4. Для DG15 клієнт виконує AA над 8-байтовим challenge, детерміновано
   виведеним зі свіжого серверного `document_auth` nonce. Сервер повторно
   виводить challenge, читає державою підписаний DG15 public key і сам
   перевіряє RSA/ECDSA-підпис. Поле `activeAuthentication=passed` саме по
   собі нічого не дозволяє.
5. Для DG14 бібліотека NFC виконує CA. Сирий DG14 входить до SOD-перевірки,
   а результат CA входить у challenge-bound AES-GCM envelope і в точні байти
   App Attest assertion. Сервер вимагає наявність CA public-key security info
   у DG14 та збіг незалежно підписаних станів. Поточна upstream-бібліотека не
   повертає ephemeral key/secure-messaging transcript, тому цей результат
   позначається `chip_authentication_attested` і не дозволяє auto-activation.
6. Клієнт шифрує DG1/DG2/DG14/DG15, DG2 portrait, neutral/challenge frames
   і AA transcript у `self-hosted-envelope-v3` через X25519/HKDF-SHA256/
   AES-256-GCM. Auth бачить лише ciphertext.
7. Auth споживає обидва nonce рівно один раз, перевіряє App Attest assertion
   над точними request bytes і assertion counter.
8. Auth надсилає envelope до приватного worker як
   `self-hosted-forward-v2`. Запит має HMAC, timestamp і випадковий nonce.
   Process-shared replay-cache атомарно споживає nonce; недоступний cache
   відхиляє запит.
9. Одноразовий worker розшифровує evidence, сам обчислює DG hashes,
   перевіряє AA, CA capability/attested state, face match, passive PAD,
   TrueDepth і активний challenge. Він повертає підписану HMAC-квитанцію.
10. Auth звіряє worker hashes із App-Attest-підписаними hashes, а потім
    перевіряє SOD, CMS, DSC → pinned CSCA та revocation status. Якщо SOD
    підписує DG14/DG15, відсутність відповідного raw DG є відмовою.
11. Одна транзакційна v7-функція з advisory locks перевіряє account,
    ban, duplicate document і записує assurance.

## Assurance policy

| Доказ документа | Результат |
|---|---|
| PA + server-verified AA | `active_authentication`; може перейти до auto-activation після calibration gate |
| PA + CA status, DG14 у SOD, state bound to App Attest, без server-verifiable transcript | `chip_authentication_attested`; тільки `pending_review` |
| Лише PA, документ без AA | `passive_only`; тільки `pending_review` |
| DG15 є, але AA не пройдено | Відмова |
| DG14 містить CA key, але CA не пройдено | Відмова |

App Attest-bound CA status сильніше за вільний client boolean, але це ще не
серверна перевірка CA. Відповідно до TR-03110, доказ має спиратися на
ephemeral-static key agreement та успішний secure messaging під новими
session keys. До форку NFC-бібліотеки, передачі мінімального перевірюваного
транскрипту та незалежного review CA-only документ не отримує Verified ID
автоматично. Складний live relay також лишається окремим residual risk.

## Дані та межа очищення

Auth тимчасово тримає SOD, DG hashes, ciphertext та nonce, але не plaintext
DG або зображення. Plaintext існує лише в RAM worker з `max_requests=1`.
Mutable buffers затираються в `finally`, після відповіді ОС знищує address
space. Production runtime також вимагає:

- read-only rootfs і приватний `tmpfs`;
- `RLIMIT_CORE=0`, без swap;
- `cap_drop: ALL`, `no-new-privileges`;
- internal network без published biometric port;
- вимкнені access/body logs;
- filesystem nonce-cache з mode `0700`, спільний для worker-процесів.

Після успіху зберігаються лише peppered document token, стан Verified ID та
мінімальний receipt: request UUID, policy/model hashes, HMAC receipt,
timestamp, protocol v7 і `document_assurance`. MRZ, номер документа, DG,
фотографії, embeddings та biometric scores не зберігаються.

## Калібрування та rollout

Production worker не повертає `passed`, доки exact aggregate report:

- не пройшов Ed25519-перевірку;
- не збігається SHA-256 report ID;
- не збігається model-set hash;
- не збігається policy version;
- не має достатніх незалежних APCER/BPCER та FMR/FNMR вимірів.

Shadow lane доступний лише server-side allowlist, завжди повертає
`evaluationOnly=true` і завершується до document token та будь-якої мутації
БД. Він корисний для збору фізичних вимірів, але не є підставою для
production activation.

Повний gate та поетапний rollout:
[`PRODUCTION_RELEASE_GATE_V7.md`](../Provenance/PRODUCTION_RELEASE_GATE_V7.md).
