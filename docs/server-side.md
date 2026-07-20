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

// 3. СТРОГА СХЕМА: кожне поле — whitelist, невідоме значення = 400.
//    ЖОДНОГО поля документа в тілі немає.
const { method, session, liveness, faceMatch, faceModel, sod, dgHashes,
        protocolVersion, endpoint } = req.body || {};

if (method !== 'nfc_passport')                        return res.status(400).json({ error: '…' });
if (protocolVersion !== 3)                            return res.status(400).json({ error: '…' });
if (endpoint !== '/auth/verify/approve')              return res.status(400).json({ error: '…' });
if (faceMatch !== 'passed' || faceModel !== 'coreml') return res.status(400).json({ error: '…' });
if (liveness !== 'depth' && liveness !== 'heuristic') return res.status(400).json({ error: '…' });
if (typeof sod !== 'string' || sod.length === 0)      return res.status(400).json({ error: 'SOD обовʼязковий' });
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

const level = liveness === 'depth' ? 'strong' : 'standard';
const storedMethod = method + '+pa' + (liveness === 'depth' ? '+depth' : '');

// 6. Запис у базу: прапорець, дата, метод. SOD НЕ зберігається —
//    тимчасова тека видаляється одразу після перевірки.
await hasuraAdmin(
  `mutation($id: uuid!, $m: String!, $at: timestamptz!) {
     update_contributors_by_pk(pk_columns:{id:$id},
       _set:{ verified:true, verified_at:$at, verification_method:$m }) { id }
   }`,
  { id: contributorId, m: storedMethod, at: new Date().toISOString() }
);

return res.json({ ok: true, verified: true, level, passiveAuthentication: pa.status });
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
