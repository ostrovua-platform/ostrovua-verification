# Що робить сервер при підтвердженні верифікації

> **Джерело істини — [`Server/verify_approve.route.js`](../Server/verify_approve.route.js):**
> ДОСЛІВНА виписка реального маршруту `/auth/verify/approve` з продакшн
> `server.js` (з ланцюгом App Attest: rawBody-захоплення, challenge,
> `verifyAssertion`, атомарний counter). Фрагмент нижче — стислий огляд,
> НЕ дослівний код (раніше формулювання «byte-for-byte» було неточним —
> виправлено, аудит F1). Passive Authentication —
> [`Server/passiveauth.js`](../Server/passiveauth.js).

```js
// 1. Авторизація: JWT користувача (contributor_id — з клеймів)
// 2. App Attest: assertion перевіряється над hash(challenge ‖ rawBody),
//    counter (compare-and-swap) захищає від replay. rawBody — дослівні
//    байти тіла, захоплені express.json { verify } ДО парсингу.
const okAttest = await verifyDeviceAttestation(req, contributorId);
if (!okAttest) return res.status(403).json({ error: 'Device attestation required' });

// 3. СТРОГА СХЕМА (F3): НЕВІДОМІ ключі відхиляються ЯВНО — сама
//    деструктуризація JS їх не ловить. Дозволений рівно цей набір.
const ALLOWED_KEYS = new Set(['method','liveness','faceMatch','faceModel',
  'sod','dgHashes','protocolVersion','endpoint','challengeId','session']);
if (Object.keys(req.body || {}).some(k => !ALLOWED_KEYS.has(k)))
  return res.status(400).json({ error: 'Невідомі поля payload' });

const { method, session, liveness, faceMatch, faceModel, sod, dgHashes,
        protocolVersion, endpoint, challengeId } = req.body || {};

if (method !== 'nfc_passport')                        return res.status(400).json({ error: '…' });
if (protocolVersion !== 3)                            return res.status(400).json({ error: '…' });
if (endpoint !== '/auth/verify/approve')              return res.status(400).json({ error: '…' });
if (typeof challengeId !== 'string' || !challengeId)  return res.status(400).json({ error: '…' }); // F2
if (session !== undefined && typeof session !== 'string') return res.status(400).json({ error: '…' });
if (faceMatch !== 'passed' || faceModel !== 'coreml') return res.status(400).json({ error: '…' });
// ПОЛІТИКА: єдиний рівень видачі — depth-backed strong.
if (liveness !== 'depth') {
  return res.status(400).json({ error: 'Для верифікації потрібен пристрій з Face ID (TrueDepth).' });
}
if (typeof sod !== 'string' || sod.length === 0 || sod.length > 96*1024)
  return res.status(400).json({ error: 'SOD відсутній або завеликий' });
if (!isValidDgHashes(dgHashes)) return res.status(400).json({ error: '…' }); // {dg1,dg2}, hex за алгоритмом
// … + перевірка форми dgHashes

// 4. Passive Authentication — ОБОВʼЯЗКОВА. «Basic»-видачі без PA
//    не існує: немає криптодоказу справжності документа — немає
//    Verified ID. Період розкатки завершено.
const pa = await passiveauth.verifySOD({ sodBase64: sod, dgHashes });
if (pa.status !== 'passed') {
  return res.status(pa.status === 'unavailable' ? 503 : 400)
            .json({ error: 'Документ не пройшов криптографічну перевірку справжності' });
}

// 5. «Один документ = один акаунт» + бан документа (fail-closed):
//    token = HMAC-SHA256(pepper, державний хеш DG1 із SOD).
//    Жодного персонального поля; відновити дані з токена неможливо.
const docToken = crypto.createHmac('sha256', DOC_PEPPER)
  .update('doc-token-v1:' + pa.sodDG1Hash).digest('hex');

const dt = await hasuraAdmin(/* byToken + byContributor lookup */);
const existing = dt.byToken?.[0];
if (existing?.status === 'banned')
  return res.status(403).json({ error: 'Цей документ заблоковано за порушення правил спільноти.' });
if (existing?.contributor_id && existing.contributor_id !== contributorId)
  return res.status(409).json({ error: 'Цей документ уже використано для верифікації іншого акаунта.' });
// … звільнення старого токена при зміні паспорта + upsert привʼязки
// (повна логіка — у продакшн-обробнику; без робочої дедуплікації
// Verified ID не видається — 503)

// Єдиний рівень: strong. Типізована колонка identity_assurance —
// authorization boundary, а не парсинг method-рядка.
const level = 'strong';
const storedMethod = method + '+pa+depth';

// 6. Запис у базу: прапорець, дата, метод, рівень. SOD НЕ зберігається —
//    тимчасова тека видаляється одразу після перевірки.
await hasuraAdmin(
  `mutation($id: uuid!, $m: String!, $at: timestamptz!, $a: String!) {
     update_contributors_by_pk(pk_columns:{id:$id},
       _set:{ verified:true, verified_at:$at, verification_method:$m,
              identity_assurance:$a }) { id }
   }`,
  { id: contributorId, m: storedMethod, at: new Date().toISOString(), a: level }
);

return res.json({ ok: true, verified: true, level, passiveAuthentication: pa.status });
```

У таблиці `contributors` після верифікації зʼявляються чотири значення:

| Поле                  | Приклад                    |
|-----------------------|----------------------------|
| `verified`            | `true`                     |
| `verified_at`         | `2026-07-20T12:00:00Z`     |
| `verification_method` | `nfc_passport+pa+depth`    |
| `identity_assurance`  | `strong`                   |

`+pa` — справжність даних чипа доведена криптографічно (Passive
Authentication за запіненими CSCA України); `+depth` — жива
присутність підтверджена мапою глибини TrueDepth. Інших рівнів
видачі не існує: без PA або без depth верифікація не проходить.

Полів для номера документа, імені з паспорта, дати народження,
громадянства чи фото в схемі бази **не існує** — зберігати їх нікуди,
навіть якби застосунок їх надіслав (а він не надсилає). SOD після
перевірки видаляється.

Додатково зберігається **токен документа** (`document_tokens`):
`HMAC-SHA256(секретний pepper, хеш DG1 із SOD)` — односторонній,
без жодного персонального поля. Призначення: «один паспорт = один
акаунт» і бан документа за порушення правил. Відновити з токена
дані документа неможливо; pepper зберігається поза базою.
Деталі і чесні межі — threat-model.md.

## CSCA masterlist

Довірені корені — masterlist ICAO PKD (або німецький BSI /
нідерландський NPKD), відфільтрований до `C=UA`:
`Server/fetch_masterlist.sh` + `Server/extract_certs.py`.
Оновлення — раз на пів року (держави ротують CSCA).
