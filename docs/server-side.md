# Що робить сервер при підтвердженні верифікації

Точний фрагмент обробника `POST /auth/verify/approve` з продакшн-сервера
(auth-мікросервіс, Node.js). Це ВСЕ, що сервер отримує і зберігає.

```js
// 1. Авторизація: JWT користувача (contributor_id — з клеймів)
// 2. App Attest: запит прийнято лише зі справжнього застосунку
const okAttest = await verifyDeviceAttestation(req, contributorId);
if (!okAttest) return res.status(403).json({ error: 'Device attestation required' });

// 3. Тіло запиту: ЛИШЕ метод і (опційно) id QR-сесії десктопа
const { method, session } = req.body || {};

// 4. Запис у базу: прапорець, дата, метод. Крапка.
await hasuraAdmin(
  `mutation($id: uuid!, $m: String!, $at: timestamptz!) {
     update_contributors_by_pk(pk_columns:{id:$id},
       _set:{ verified:true, verified_at:$at, verification_method:$m }) { id }
   }`,
  { id: contributorId, m: method || 'nfc_passport', at: new Date().toISOString() }
);

return res.json({ ok: true, verified: true });
```

У таблиці `contributors` після верифікації зʼявляються три значення:

| Поле                  | Приклад                    |
|-----------------------|----------------------------|
| `verified`            | `true`                     |
| `verified_at`         | `2026-07-19T12:00:00Z`     |
| `verification_method` | `nfc_passport`             |

Полів для номера документа, імені з паспорта, дати народження,
громадянства чи фото в схемі бази **не існує** — зберігати їх нікуди,
навіть якби застосунок їх надіслав (а він не надсилає).
