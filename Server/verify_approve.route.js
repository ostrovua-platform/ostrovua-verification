// ═══════════════════════════════════════════════════════════════════
//  РЕАЛЬНИЙ маршрут /auth/verify/approve та вся ланцюг App Attest —
//  ДОСЛІВНА виписка з продакшн backend/auth/server.js (не ілюстрація).
//
//  Санітизація: прибрано лише не повʼязані з верифікацією маршрути
//  (login/register/push/calls). Секрети — у .env, тут їх немає.
//  Залежності: express, jsonwebtoken, crypto, ./appattest, ./passiveauth,
//  hasuraAdmin() (GraphQL admin-клієнт), requireContributor(), rateLimit.
//
//  Тут доводиться END-TO-END (аудит F4):
//   1. rawBody захоплюється ДО JSON-парсингу (express.json verify);
//   2. саме ці байти йдуть у verifyAssertion (bodyBytes: req.rawBody);
//   3. challengeId читається з req.body без ре-серіалізації;
//   4. challenge споживається рівно раз (consumeChallenge, owner-check);
//   5. assertion counter оновлюється АТОМАРНО (compare-and-swap).
//
//  Строга схема (F3): невідомі ключі payload → 400; форма dgHashes
//  валідовна; ліміт розміру SOD на межі маршруту.
// ═══════════════════════════════════════════════════════════════════
'use strict';
// express.json rawBody capture (дослівні байти для App Attest):

// SHA256(challenge ‖ rawBody), тож перевіряти треба саме ті байти,
// що надіслав клієнт, а не пере-серіалізований JSON.
// express.json rawBody (split limits, аудит P1-07):

const captureRaw = (req, _res, buf) => { req.rawBody = buf; };
const bigJson   = express.json({ limit: '40mb',  verify: captureRaw });
const smallJson = express.json({ limit: '512kb', verify: captureRaw });
app.use((req, res, next) =>
  (req.path === '/auth/upload' ? bigJson : smallJson)(req, res, next));
app.use(express.urlencoded({ extended: true, limit: '512kb' }));



app.post('/auth/verify/challenge', rateLimit, (req, res) => {
  const contributorId = requireContributor(req, res);
  if (!contributorId) return;
  try {
    const { id, challenge } = appattest.issueChallenge(contributorId);
    return res.json({ challengeId: id, challenge });
  } catch (e) {
    return res.status(503).json({ error: 'Спробуй пізніше.' });
  }
});


async function verifyAppAttestAssertion(req, contributorId) {
  const assertionB64 = req.headers['x-app-attest'];
  const keyId        = req.headers['x-attest-key'];
  const challengeId  = req.body?.challengeId;
  if (!assertionB64 || !keyId || !challengeId) return false;

  const challengeBytes = appattest.consumeChallenge(challengeId, contributorId);
  if (!challengeBytes) return false;

  try {
    const d = await hasuraAdmin(
      `query($k: String!, $c: uuid!) {
         attest_keys(where:{key_id:{_eq:$k}, contributor_id:{_eq:$c}}, limit:1)
         { key_id public_key_pem counter }
       }`,
      { k: keyId, c: contributorId }
    );
    const rec = d.attest_keys?.[0];
    if (!rec) return false;

    const newCounter = appattest.verifyAssertion({
      assertionB64, publicKeyPem: rec.public_key_pem,
      challengeBytes,
      bodyBytes: req.rawBody,          // дослівні байти canonical payload
      storedCounter: rec.counter,
    });
    // АТОМАРНО (compare-and-swap, аудит P1-03): counter приймається
    // лише якщо в БАЗІ він досі менший — два паралельні запити з тим
    // самим assertion не пройдуть обидва (перший виграє, другий — 0 рядків).
    const upd = await hasuraAdmin(
      `mutation($k: String!, $n: bigint!, $at: timestamptz!) {
         update_attest_keys(
           where:{ key_id:{_eq:$k}, counter:{_lt:$n} },
           _set:{ counter:$n, last_used_at:$at }) { affected_rows }
       }`,
      { k: keyId, n: newCounter, at: new Date().toISOString() }
    );
    if ((upd.update_attest_keys?.affected_rows ?? 0) !== 1) {
      console.warn('[verify/assertion] counter CAS conflict (можливий replay)');
      return false;
    }
    return true;
  } catch (e) {
    console.warn('[verify/assertion]', e.message);
    return false;
  }
}


async function verifyDeviceAttestation(req, contributorId) {
  if (req.headers['x-app-attest']) return verifyAppAttestAssertion(req, contributorId);
  return false;
}


function isValidDgHashes(v) {
  if (typeof v !== 'object' || v === null) return false;
  if (Object.keys(v).sort().join(',') !== 'dg1,dg2') return false;
  for (const dg of ['dg1', 'dg2']) {
    const group = v[dg];
    if (typeof group !== 'object' || group === null) return false;
    const algs = Object.keys(group);
    if (algs.length === 0 || algs.length > 5) return false;
    for (const alg of algs) {
      const want = DG_HEX_LENGTHS[alg];
      const hex = group[alg];
      if (!want || typeof hex !== 'string' || hex.length !== want ||
          !/^[0-9a-fA-F]+$/.test(hex)) return false;
    }
  }
  return true;
}


app.post('/auth/verify/approve', rateLimit, async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Не авторизовано' });

  let payload;
  try { payload = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch(e) { return res.status(401).json({ error: 'Недійсний токен' }); }

  const contributorId = payload['https://hasura.io/jwt/claims']?.['x-hasura-contributor-id'];
  if (!contributorId) return res.status(401).json({ error: 'Не авторизовано' });

  const okAttest = await verifyDeviceAttestation(req, contributorId);
  if (!okAttest) return res.status(403).json({ error: 'Device attestation required' });

  // Тіло — канонічний payload, підписаний App Attest assertion.
  // verifyDeviceAttestation перевіряє assertion над hash(challenge ‖ body)
  // та assertion counter (replay).
  //
  // СТРОГА СХЕМА (аудит P0-05, F3): відхиляємо НЕВІДОМІ ключі явно —
  // JS-деструктуризація сама їх не ловить. Дозволений рівно цей набір.
  const body = req.body || {};
  const ALLOWED_KEYS = new Set([
    'method', 'liveness', 'faceMatch', 'faceModel', 'sod', 'dgHashes',
    'protocolVersion', 'endpoint', 'challengeId', 'session',
  ]);
  const extraneous = Object.keys(body).filter(k => !ALLOWED_KEYS.has(k));
  if (extraneous.length) {
    return res.status(400).json({ error: 'Невідомі поля payload: ' + extraneous.join(', ') });
  }

  const { method, session, liveness, faceMatch, faceModel, sod, dgHashes,
          protocolVersion, endpoint, challengeId } = body;

  if (method !== 'nfc_passport') {
    return res.status(400).json({ error: 'Недопустимий метод верифікації' });
  }
  if (protocolVersion !== 3) {
    return res.status(400).json({ error: 'Застаріла версія застосунку. Онови OstrovUA.' });
  }
  if (endpoint !== '/auth/verify/approve') {
    return res.status(400).json({ error: 'Недопустимий payload' });
  }
  // challengeId завжди додає AppAttestService перед канонізацією (F2).
  if (typeof challengeId !== 'string' || challengeId.length === 0) {
    return res.status(400).json({ error: 'challengeId обовʼязковий' });
  }
  // session — опційний токен десктоп-QR-сесії; якщо є, лише рядок.
  if (session !== undefined && typeof session !== 'string') {
    return res.status(400).json({ error: 'Недопустимий session' });
  }
  // Обличчя ОБОВʼЯЗКОВО має збігтись, модель — лише CoreML
  // (vision_fallback заборонений у release і сервером теж).
  if (faceMatch !== 'passed' || faceModel !== 'coreml') {
    return res.status(400).json({ error: 'Face verification not acceptable' });
  }
  // ПОЛІТИКА: єдиний рівень видачі — depth-backed strong (аудит P0-01).
  if (liveness !== 'depth') {
    return res.status(400).json({ error: 'Для верифікації потрібен пристрій з Face ID (TrueDepth).' });
  }
  if (typeof sod !== 'string' || sod.length === 0 || sod.length > 96 * 1024) {
    return res.status(400).json({ error: 'SOD відсутній або завеликий' });
  }
  // Строга форма dgHashes: рівно {dg1,dg2}, кожен — обʼєкт
  // {алгоритм → hex}, hex лише [0-9a-f], розумної довжини (F3).
  if (!isValidDgHashes(dgHashes)) {
    return res.status(400).json({ error: 'Недопустима форма dgHashes' });
  }

  // ── Passive Authentication (ICAO 9303): серверна перевірка SOD ────
  // ОБОВʼЯЗКОВА: немає криптодоказу справжності документа — немає
  // Verified ID. Обходу не існує (dev-bypass фізично видалено).
  const pa = await passiveauth.verifySOD({ sodBase64: sod, dgHashes });

  if (pa.status !== 'passed') {
    console.warn(`[verify/approve] PA REJECT ${contributorId.slice(0,8)}… status=${pa.status} reason=${pa.reason}`);
    const msg = pa.status === 'unavailable'
      ? 'Перевірка справжності документа тимчасово недоступна. Спробуй пізніше.'
      : 'Документ не пройшов криптографічну перевірку справжності';
    return res.status(pa.status === 'unavailable' ? 503 : 400).json({ error: msg });
  }

  // ── «Один документ = один акаунт» + бан документа ────────────────
  // token = HMAC(pepper, держ. хеш DG1 із SOD): односторонній,
  // детермінований. Номер паспорта НЕ зберігається і не відновлюється.
  const DOC_PEPPER = process.env.DOC_TOKEN_PEPPER || '';
  if (!DOC_PEPPER) {
    console.error('[verify/approve] DOC_TOKEN_PEPPER відсутній — верифікація зупинена (fail-closed)');
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }
  const docToken = crypto.createHmac('sha256', DOC_PEPPER)
    .update('doc-token-v1:' + pa.sodDG1Hash).digest('hex');

  try {
    // Зміна паспорта: звільняємо СВІЙ попередній токен (той самий акаунт —
    // не гонка), інакше унікальний індекс contributor_id завадить привʼязці.
    await hasuraAdmin(
      `mutation($c: uuid!, $t: String!) {
         delete_document_tokens(where:{ contributor_id:{_eq:$c},
                                        token:{_neq:$t}, status:{_eq:"active"} }) { affected_rows }
       }`,
      { c: contributorId, t: docToken }
    );

    // АТОМАРНА привʼязка (аудит P0-02): один запит INSERT … ON CONFLICT
    // DO UPDATE … WHERE. Оновлюємо contributor_id ЛИШЕ якщо рядок ще
    // не привʼязаний (NULL) або вже наш, і статус active. Два акаунти,
    // що одночасно клеймлять один документ, серіалізуються на PK токена:
    // перший привʼязує, другий не проходить WHERE і повертає 0 рядків.
    const claim = await hasuraAdmin(
      `mutation($obj: document_tokens_insert_input!, $c: uuid!, $at: timestamptz!) {
         insert_document_tokens_one(object:$obj,
           on_conflict:{ constraint: document_tokens_pkey,
                         update_columns:[contributor_id, last_verified_at],
                         where:{ _or:[{contributor_id:{_is_null:true}},
                                      {contributor_id:{_eq:$c}}],
                                 status:{_eq:"active"} } }
         ) { token contributor_id }
       }`,
      { obj: { token: docToken, contributor_id: contributorId,
               last_verified_at: new Date().toISOString() }, c: contributorId,
        at: new Date().toISOString() }
    );

    const bound = claim.insert_document_tokens_one;
    if (!bound || bound.contributor_id !== contributorId) {
      // Привʼязка не вдалась → зʼясовуємо чому (забанений / чужий)
      const info = await hasuraAdmin(
        `query($t: String!) { document_tokens(where:{token:{_eq:$t}}, limit:1) { contributor_id status } }`,
        { t: docToken }
      );
      const row = info.document_tokens?.[0];
      if (row?.status === 'banned') {
        console.warn(`[verify/approve] BANNED DOC ${contributorId.slice(0,8)}…`);
        return res.status(403).json({ error: 'Цей документ заблоковано за порушення правил спільноти.' });
      }
      console.warn(`[verify/approve] DUPLICATE DOC ${contributorId.slice(0,8)}…`);
      return res.status(409).json({ error: 'Цей документ уже використано для верифікації іншого акаунта.' });
    }
  } catch (e) {
    // Fail-closed: без роботи дедуплікації Verified ID не видаємо
    console.error('[verify/approve] document_tokens:', e.message);
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }

  // Єдиний рівень: strong. Типізована колонка identity_assurance —
  // authorization boundary (аудит P0-01), а не парсинг method-рядка.
  const level = 'strong';
  const storedMethod = method + '+pa+depth';

  try {
    await hasuraAdmin(
      `mutation($id: uuid!, $m: String!, $at: timestamptz!, $a: String!) {
         update_contributors_by_pk(pk_columns:{id:$id},
           _set:{ verified:true, verified_at:$at, verification_method:$m,
                  identity_assurance:$a }) { id }
       }`,
      { id: contributorId, m: storedMethod, at: new Date().toISOString(), a: level }
    );
    console.log(`[verify/approve] ${contributorId.slice(0,8)}… level=${level} pa=passed alg=${pa.algorithm || '-'} live=${liveness} issuer_ok=1`);
    // Якщо флоу стартував з десктопа через QR — повідомити його модалку.
    if (session) {
      const s = getVerifySession(session);
      if (s && s.contributorId === contributorId) s.status = 'approved';
    }
    return res.json({ ok: true, verified: true, level, passiveAuthentication: pa.status });
  } catch(e) {
    console.error('[verify/approve]', e.message);
    return res.status(500).json({ error: 'Помилка сервера' });
  }
});
