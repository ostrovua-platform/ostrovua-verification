# Production release gate — Verified ID protocol v7

Статус на 2026-07-25: **NO-GO для автоматичної production-активації**.

Локальна реалізація готова до інтеграційного/staging тесту. Production ще не
розгорнуто з перевіреним v7 artifact set. Усі dark-прапорці мають залишатися:

```text
SELF_HOSTED_VERIFICATION_ENABLED=0
BIOMETRIC_CALIBRATION_APPROVED=0
BIOMETRIC_SHADOW_MODE_ENABLED=0
SERVER_OWNED_CA_ENABLED=0
```

Shadow lane може лишатися окремо ввімкненим лише для точного UUID allowlist.
Він не активує Verified ID.

## A. Криптографічний документ

- [x] iOS читає DG14/DG15 разом із COM/SOD/DG1/DG2.
- [x] DG15 виконує AA зі свіжим server-derived challenge.
- [x] Worker сам перевіряє DG15 key та RSA/ECDSA AA signature.
- [x] DG14/15 hashes входять у authoritative SOD check.
- [x] DG14 CA state зв’язаний із document nonce, DG14 digest та App Attest.
- [x] Вільний `aaPassed` не є доказом: AA signature перевіряється worker.
- [x] CA status без server-verifiable transcript не дає auto-activation:
  `chip_authentication_attested` і тільки review.
- [x] Форк NFC-бібліотеки експортує обмежений relay: metadata DG14,
  server-owned ephemeral public key та рівно один protected GET CHALLENGE.
- [x] Auth незалежно перевіряє ECDH/AES secure-messaging MAC і plaintext
  challenge, не довіряючи `caPassed` від клієнта.
- [x] Одноразова CA-квитанція зв’язана з contributor, App Attest key,
  document challenge та worker-computed DG14 SHA-256.
- [x] CA-квитанція споживається атомарно в тій самій DB-транзакції, що й
  активація Verified ID.
- [x] Без server-verified AA або server-owned CA результат тільки
  `pending_review`.
- [x] Protocol v6 і envelope v1/v2 відхиляються.
- [x] Підготовлено privacy-minimizing corpus runner: тільки pseudonymous
  metadata/result/digests, без DG1/DG2, фото чи raw APDU transcript.
- [ ] Staging corpus: реальні AA RSA, AA ECDSA, CA-only та passive-only
  документи різних поколінь/країн.
- [ ] Окремий controlled live-relay test для CA residual risk.
- [ ] Незалежний cryptography review реалізації RSA ISO 9796 та DG14 parser.

## B. App Attest, replay та rate limiting

- [x] App Attest key створюється до document/liveness challenge.
- [x] Liveness і document authentication мають різні one-shot purposes.
- [x] Internal HMAC запит має timestamp + 128-bit nonce.
- [x] Process-shared replay cache атомарно споживає nonce.
- [x] Replay cache fail-closed при I/O/capacity/corruption failure.
- [x] Persistent limiter рахує одну спробу на liveness challenge.
- [x] document_auth та approve виконують non-incrementing DB lock check.
- [x] Відсутня account/device limiter identity дає відмову.
- [ ] Fault-injection staging test: PostgreSQL down/timeout/malformed row.
- [ ] Multi-worker concurrency test: однаковий HMAC nonce приймається рівно
  один раз.
- [ ] Load test підтверджує, що capacity exhaustion не дає fail-open.

## C. PAD і face match

- [x] Shadow/evaluation result криптографічно відокремлений від activation.
- [x] Calibration report прив'язаний до exact policy/model hashes.
- [x] Evaluator v3 повторно обчислює component та end-to-end рішення через
  production `policy.decide`; legacy single-score calibration відхиляється.
- [x] Зміна report/model/policy/signature анулює approval.
- [x] Pinned SFace/YuNet/MiniFAS/MediaPipe artifacts проходять integrity load
  та reproducible live/print/screen model smoke на зафіксованих fixtures.
- [ ] Незалежні bona-fide випробування: різні люди, вік, освітлення,
  відтінки шкіри, окуляри, iPhone/OS.
- [ ] Print corpus.
- [ ] Screen/static/replay corpus.
- [ ] 3D mask corpus.
- [ ] Camera injection corpus на контрольованому стенді.
- [ ] Reactive deepfake corpus.
- [ ] APCER per attack + 95% CI в межах затвердженої цілі.
- [ ] BPCER + demographic slices + 95% CI в межах цілі.
- [ ] FMR/FNMR + 95% CI в межах цілі.
- [ ] Незалежна сторона підписала calibration report Ed25519 key.

Будь-яка незакрита позиція C є release-blocker. Ручні успішні прогони та
скриншоти не замінюють статистичний звіт.

## D. Privacy/runtime

- [x] Auth не має envelope private key.
- [x] Plaintext DG/кадри обробляє one-request worker.
- [x] Код затирає mutable evidence references/buffers.
- [ ] Staging runtime: `max_requests=1` перевірений фактичним PID change.
- [ ] Read-only rootfs, private tmpfs, `RLIMIT_CORE=0`, no swap.
- [ ] `cap_drop: ALL`, `no-new-privileges`, PID/memory/time limits.
- [ ] Biometric port не опублікований; egress заборонений.
- [ ] DB/log/filesystem scan після adversarial прогону не знаходить MRZ,
  DG, фотографії, embeddings або request body.
- [ ] Backup/restore drill підтверджує відсутність біометричних payload.
- [ ] Privacy notice і retention statement пройшли юридичний review.

## E. Database та rollout

- [x] V7 functions атомарно записують `document_assurance`.
- [x] Auto activation приймає лише server-verified AA або одноразовий
  `chip_authentication_server` assurance.
- [x] Client-reported/attested CA лишається review-only.
- [x] Passive-only створює review reason `passive_document_no_aa_or_ca`.
- [x] Локальні backend security tests: 60/60; npm production audit: 0.
- [x] Biometric Python/model tests: 41/41 з pinned live/print/screen fixtures.
- [x] Поточний iOS source збирається для device і simulator без code-signing.
- [ ] Міграції виконані на staging snapshot і перевірені rollback/restore.
- [ ] Advisory-lock race test: duplicate document, two accounts, pepper
  rotation, concurrent receipt.
- [ ] Production artifact hashes збігаються з reviewed commit.
- [ ] Production legacy route фізично замінено, але flags ще `0`.
- [ ] Read-only smoke: health, masterlist/DSC/CRL freshness, App Attest,
  biometric key ID, replay cache та limiter.

## Поетапне ввімкнення

1. **Shadow only:** 0% activation, збір незалежного holdout.
2. **Staging:** повний corpus, fault injection, race/load tests.
3. **Production dark deploy:** v7 binaries/migrations, flags `0`, лише health.
4. **1% allowlist:** тільки після підписаного report; 24–48 годин.
5. **5% → 25% → 100%:** кожен крок після review метрик та incidents.

Негайний rollback до `SELF_HOSTED_VERIFICATION_ENABLED=0`, якщо:

- будь-який confirmed presentation/replay attack отримав Verified ID;
- limiter/replay/App Attest/PA/AA/CA dependency стала fail-open;
- model/report/policy hash не збігається;
- виявлено biometric/document payload у persistence або logs;
- BPCER/FMR/APCER перевищує підписані межі;
- spike `E-202`, latency або worker crashes перевищує затверджений SLO.

Фінальне GO-рішення підписують щонайменше security owner, backend owner,
iOS owner, privacy/legal owner та незалежний calibration reviewer. До цього
цей документ є технічним gate, а не сертифікатом безпеки.
