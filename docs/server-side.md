# Що робить сервер при підтвердженні верифікації

Точний фрагмент обробника `POST /auth/verify/approve` з продакшн-сервера
(auth-мікросервіс, Node.js). Повний код Passive Authentication —
[`Server/passiveauth.js`](../Server/passiveauth.js) (дослівна копія
продакшн-модуля).

```js
// 1. Авторизація: JWT користувача (contributor_id — з клеймів)
// 2. App Attest: assertion перевіряється над hash(challenge ‖ тіло запиту),
//    counter захищає від replay. Тіло — канонічний JSON, підмінити
//    його після підпису неможливо.
const okAttest = await verifyDeviceAttestation(req, contributorId);
if (!okAttest) return res.status(403).json({ error: 'Device attestation required' });

// 3. Тіло: enum-результати + SOD + хеші DG. ЖОДНОГО поля документа.
const { method, session, liveness, faceMatch, faceModel, sod, dgHashes } = req.body || {};

const ALLOWED_METHODS = ['nfc_passport'];
if (!ALLOWED_METHODS.includes(method)) return res.status(400).json({ error: '…' });
if (faceMatch !== 'passed')            return res.status(400).json({ error: '…' });

// 4. Passive Authentication (ICAO 9303): сервер САМ перевіряє
//    підпис держави над даними чипа — клієнту не вірить на слово.
//    Див. Server/passiveauth.js: цілісність CMS-підпису → звірка
//    хешів DG1/DG2 з підписаними в SOD → ланцюжок DSC → CSCA України.
let pa = { status: 'failed', reason: 'sod_missing' };
if (typeof sod === 'string' && sod.length > 0) {
  pa = passiveauth.verifySOD({ sodBase64: sod, dgHashes });
}

// Підроблений/битий SOD чи розбіжність хешів — відмова ЗАВЖДИ.
const HARD_FAIL = ['sod_malformed', 'cms_signature_invalid', 'lds_parse_failed',
                   'dg_hash_mismatch', 'issuer_not_ukraine'];
if (pa.status === 'failed' && HARD_FAIL.includes(pa.reason)) {
  return res.status(400).json({ error: 'Документ не пройшов криптографічну перевірку справжності' });
}
// PA_ENFORCE=1: без пройденої PA верифікації немає (жорсткий режим).
if (PA_ENFORCE && pa.status !== 'passed') return res.status(400).json({ error: '…' });

const paPassed = pa.status === 'passed';
const storedMethod = paPassed ? method + '+pa' : method;   // чесна позначка в базі

// 5. Запис у базу: прапорець, дата, метод. SOD НЕ зберігається —
//    тимчасова тека видаляється одразу після перевірки.
await hasuraAdmin(
  `mutation($id: uuid!, $m: String!, $at: timestamptz!) {
     update_contributors_by_pk(pk_columns:{id:$id},
       _set:{ verified:true, verified_at:$at, verification_method:$m }) { id }
   }`,
  { id: contributorId, m: storedMethod, at: new Date().toISOString() }
);

return res.json({ ok: true, verified: true, level: paPassed ? 'strong' : 'basic',
                  passiveAuthentication: pa.status });
```

У таблиці `contributors` після верифікації зʼявляються три значення:

| Поле                  | Приклад                    |
|-----------------------|----------------------------|
| `verified`            | `true`                     |
| `verified_at`         | `2026-07-19T12:00:00Z`     |
| `verification_method` | `nfc_passport+pa`          |

`+pa` означає: справжність даних чипа доведена криптографічно
(Passive Authentication за CSCA України). Без `+pa` — перехідний
«basic»-рівень (див. режим `PA_ENFORCE` у threat-model.md).

Полів для номера документа, імені з паспорта, дати народження,
громадянства чи фото в схемі бази **не існує** — зберігати їх нікуди,
навіть якби застосунок їх надіслав (а він не надсилає). SOD після
перевірки видаляється; його хеші в базу не пишуться.

## CSCA masterlist

Довірені корені — masterlist ICAO PKD (або німецький BSI /
нідерландський NPKD), відфільтрований до `C=UA`:
`Server/fetch_masterlist.sh` + `Server/extract_certs.py`.
Оновлення — раз на пів року (держави ротують CSCA).
