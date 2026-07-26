// ═══════════════════════════════════════════════════════════════════
//  ІСТОРИЧНИЙ security-review snapshot маршруту /auth/verify/approve.
//  Не є deploy source і навмисно не оновлюється частковими вставками:
//  єдине актуальне джерело production-коду — ./server.js. Автоматичні
//  security-invariant тести також читають ./server.js безпосередньо.
//
//  Санітизація: прибрано лише не повʼязані з верифікацією маршрути
//  (login/register/push/calls). Секрети — у .env, тут їх немає.
//  Залежності: express, jsonwebtoken, crypto, ./appattest, ./passiveauth,
//  hasuraAdmin() (GraphQL admin-клієнт), hasuraSQL() (admin run_sql через
//  /v2/query — для виклику plpgsql-функції прямо в Postgres),
//  requireContributor(), rateLimit, db.pool.
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
const verificationPolicy = require('./verification_policy');
const { parseSelfHostedEnvelope } = require('./self_hosted_contract');
const biometricClient = require('./biometric_client');
// express.json rawBody capture (дослівні байти для App Attest):

// SHA256(challenge ‖ rawBody), тож перевіряти треба саме ті байти,
// що надіслав клієнт, а не пере-серіалізований JSON.
// express.json rawBody (split limits, аудит P1-07):

const captureRaw = (req, _res, buf) => { req.rawBody = buf; };
const bigJson   = express.json({ limit: '40mb',  verify: captureRaw });
const verifyJson = express.json({ limit: '12mb', verify: captureRaw });
const smallJson = express.json({ limit: '512kb', verify: captureRaw });
app.use((req, res, next) => {
  const parser = req.path === '/auth/upload'
    ? bigJson
    : (req.path === '/auth/verify/approve' ? verifyJson : smallJson);
  return parser(req, res, next);
});
app.use(express.urlencoded({ extended: true, limit: '512kb' }));

// Persistent verification limiter. Invalid/missing keys and any database
// failure are authentication failures, never permission to fall back to a
// process-local counter.
function rlKeyValid(key) {
  return /^acct:[0-9a-fA-F-]{36}$/.test(key) ||
    /^dev:[A-Za-z0-9+/=_-]{1,64}$/.test(key);
}

function parseRlRow(row) {
  if (!row || typeof row.is_locked !== 'boolean' ||
      !Number.isInteger(Number(row.cur_tier)) ||
      (row.until !== null && row.until !== undefined &&
       Number.isNaN(new Date(row.until).getTime()))) {
    throw new Error('verification_rate_limit_response_invalid');
  }
  return {
    locked: row.is_locked,
    until: row.until || null,
    tier: Number(row.cur_tier),
  };
}

async function rlQuery(functionName, key) {
  if (!rlKeyValid(key) || !['rl_touch', 'rl_check'].includes(functionName)) {
    throw new Error('verification_rate_limit_key_invalid');
  }
  const result = await db.pool.query(
    `SELECT is_locked, until, cur_tier FROM ${functionName}($1)`,
    [key]
  );
  return parseRlRow(result.rows?.[0]);
}

const rlTouch = (key) => rlQuery('rl_touch', key);
const rlCheck = (key) => rlQuery('rl_check', key);

async function rlReset(key) {
  if (!rlKeyValid(key)) throw new Error('verification_rate_limit_key_invalid');
  await db.pool.query('SELECT rl_reset($1)', [key]);
}

function rlKeysFor(contributorId, req) {
  const keys = [];
  if (/^[0-9a-fA-F-]{36}$/.test(contributorId || '')) {
    keys.push(`acct:${contributorId}`);
  }
  const device = req.headers['x-attest-key'];
  if (typeof device === 'string' && /^[A-Za-z0-9+/=_-]{1,64}$/.test(device)) {
    keys.push(`dev:${device}`);
  }
  if (keys.length !== 2) {
    throw new Error('verification_rate_limit_identity_incomplete');
  }
  return keys;
}

function rlLockedMessage(until) {
  const milliseconds = until ? new Date(until).getTime() - Date.now() : 0;
  if (milliseconds > 300 * 24 * 3600e3) {
    return 'Верифікацію заблоковано за підозрілу активність. Звернись у підтримку (апеляція).';
  }
  const hours = Math.ceil(milliseconds / 3600e3);
  const when = hours >= 24
    ? `${Math.ceil(hours / 24)} дн.`
    : `${Math.max(1, hours)} год.`;
  return `Забагато спроб верифікації. Спробуй за ${when}.`;
}



app.post('/auth/verify/challenge', rateLimit, async (req, res) => {
  const contributorId = await requireContributor(req, res);
  if (!contributorId) return;

  const purpose = req.body?.purpose;
  const verificationMode = req.body?.verificationMode == null
    ? 'production'
    : req.body.verificationMode;
  if (!['attestation', 'liveness', 'document_auth'].includes(purpose) ||
      !['production', 'calibration'].includes(verificationMode) ||
      (purpose === 'attestation' && verificationMode !== 'production')) {
    return res.status(400).json({ error: 'Недопустиме призначення challenge' });
  }
  const calibrationChallenge = purpose !== 'attestation' &&
    verificationMode === 'calibration';
  if (calibrationChallenge && !verificationPolicy.isBiometricShadowAllowed(
    contributorId,
    process.env.BIOMETRIC_SHADOW_MODE_ENABLED,
    process.env.BIOMETRIC_SHADOW_TESTER_IDS
  )) {
    return res.status(403).json({
      error: 'Тестовий режим біометрії недоступний для цього акаунта.',
      code: 'CALIBRATION_MODE_FORBIDDEN',
    });
  }
  // Не змушуємо людину проходити NFC/PAD, коли production rollout
  // навмисно закритий. Перевіряємо kill-switch ДО rate-limit і ДО видачі
  // біометричного ключа: спроба не рахується, кадри не збираються.
  if (['liveness', 'document_auth'].includes(purpose) && !calibrationChallenge &&
      !verificationPolicy.isSelfHostedVerificationEnabled()) {
    return res.status(503).json({
      error: 'Автоматична верифікація ще не активована. Спробуй пізніше.',
      code: 'SELF_HOSTED_VERIFICATION_DISABLED',
      retryable: true,
    });
  }

  // ЛІМІТ СПРОБ liveness (анти-реплей перебору): кожна спроба бере свіжий
  // challenge → рахуємо видачі на АКАУНТ+ПРИСТРІЙ (rlKeysFor читає uuid і
  // заголовок x-attest-key). Закритий calibration lane не може активувати
  // Verified ID і доступний лише точному server-side allowlist, тому для
  // нього лишається burst-limit middleware без багатогодинної ескалації.
  if (purpose === 'liveness' && !calibrationChallenge) {
    try {
      for (const key of rlKeysFor(contributorId, req)) {
        const r = await rlTouch(key);   // SELECT … FOR UPDATE — без гонок
        if (r.locked) return res.status(429).json({ error: rlLockedMessage(r.until) });
      }
    } catch (e) {
      console.error('[verify/challenge] rate-limit unavailable');
      return res.status(503).json({
        error: 'Захист від повторних спроб тимчасово недоступний. Спробуй пізніше.',
        code: 'VERIFICATION_RATE_LIMIT_UNAVAILABLE',
        retryable: true,
      });
    }
  }
  // document_auth видається перед NFC і не повинен вдруге інкрементувати
  // одну людську спробу. Але критичний endpoint усе одно залежить від
  // доступного persistent limiter: rlCheck читає той самий рядок під
  // транзакційним lock і fail-closed повертає поточний стан.
  if (purpose === 'document_auth' && !calibrationChallenge) {
    try {
      for (const key of rlKeysFor(contributorId, req)) {
        const r = await rlCheck(key);
        if (r.locked) return res.status(429).json({ error: rlLockedMessage(r.until) });
      }
    } catch (e) {
      console.error('[verify/challenge] rate-limit unavailable');
      return res.status(503).json({
        error: 'Захист від повторних спроб тимчасово недоступний. Спробуй пізніше.',
        code: 'VERIFICATION_RATE_LIMIT_UNAVAILABLE',
        retryable: true,
      });
    }
  }

  try {
    const storedPurpose = calibrationChallenge
      ? `${purpose}_calibration`
      : purpose;
    const { id, challenge } = appattest.issueChallenge(contributorId, storedPurpose);
    if (purpose === 'liveness') {
      const key = biometricClient.loadEnvelopePublicKey();
      return res.json({
        challengeId: id,
        challenge,
        biometricKeyId: key.keyId,
        biometricPublicKey: key.publicKey,
      });
    }
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

  const challengeBytes = appattest.consumeChallenge(
    challengeId,
    contributorId,
    'attestation'
  );
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
  const groups = Object.keys(v).sort();
  if (!groups.includes('dg1') || !groups.includes('dg2') ||
      groups.some((dg) => !['dg1', 'dg2', 'dg14', 'dg15'].includes(dg))) {
    return false;
  }
  for (const dg of groups) {
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
  const contributorId = await requireContributor(req, res);
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
    'biometricEnvelope', 'verificationMode',
    'protocolVersion', 'endpoint', 'challengeId', 'session',
    'activeLiveness', 'activeLivenessChallengeId', 'activeLivenessEvidence',
    'documentAuthenticationChallengeId', 'chipAuthentication',
    'activeAuthentication',
    'faceModelVersion', 'faceMatchScore', 'faceMatchThreshold',
    'faceSampleCount', 'faceContinuityScore',
  ]);
  const extraneous = Object.keys(body).filter(k => !ALLOWED_KEYS.has(k));
  if (extraneous.length) {
    return res.status(400).json({ error: 'Невідомі поля payload: ' + extraneous.join(', ') });
  }

  const { method, session, liveness, faceMatch, faceModel, sod, dgHashes,
          protocolVersion, endpoint, challengeId,
          activeLiveness, activeLivenessChallengeId,
          documentAuthenticationChallengeId, chipAuthentication,
          activeAuthentication } = body;
  const verificationMode = body.verificationMode === undefined
    ? 'production'
    : body.verificationMode;
  if (verificationMode !== 'production' && verificationMode !== 'calibration') {
    return res.status(400).json({ error: 'Недопустимий режим верифікації' });
  }
  const evaluationOnly = verificationMode === 'calibration';
  if (evaluationOnly && protocolVersion !== verificationPolicy.PROTOCOL_VERSION) {
    return res.status(400).json({ error: 'Тестовий режим потребує актуальної версії застосунку' });
  }
  // UI видимий у TestFlight не є межею безпеки: сервер окремо перевіряє
  // закритий allowlist contributor UUID. Невідомий акаунт не запускає worker.
  if (evaluationOnly && !verificationPolicy.isBiometricShadowAllowed(contributorId)) {
    return res.status(403).json({
      error: 'Тестовий режим недоступний для цього акаунта.',
      code: 'CALIBRATION_MODE_FORBIDDEN',
    });
  }
  // Approve є окремою критичною межею. Навіть якщо liveness challenge уже
  // було видано, недоступність або lock persistent limiter не дозволяє
  // дійти до PA, біометричного worker'а чи мутації Verified ID.
  if (!evaluationOnly) {
    try {
      for (const key of rlKeysFor(contributorId, req)) {
        const r = await rlCheck(key);
        if (r.locked) return res.status(429).json({ error: rlLockedMessage(r.until) });
      }
    } catch (e) {
      console.error('[verify/approve] rate-limit unavailable');
      return res.status(503).json({
        error: 'Захист від повторних спроб тимчасово недоступний. Спробуй пізніше.',
        code: 'VERIFICATION_RATE_LIMIT_UNAVAILABLE',
        retryable: true,
      });
    }
  }

  if (method !== 'nfc_passport') {
    return res.status(400).json({ error: 'Недопустимий метод верифікації' });
  }
  // Активна liveness (challenge-response) — ОБОВʼЯЗКОВА, з привʼязкою
  // до серверного nonce (анти-реплей): challengeId має бути виданий
  // цьому користувачу й свіжий. consumeChallenge гарантує одноразовість.
  if (activeLiveness !== 'passed') {
    return res.status(400).json({ error: 'Активну перевірку присутності не пройдено' });
  }
  let activeChallengeBytes = null;
  {
    const expectedChallengePurpose = evaluationOnly
      ? 'liveness_calibration'
      : 'liveness';
    activeChallengeBytes = typeof activeLivenessChallengeId === 'string'
      ? appattest.consumeChallenge(
        activeLivenessChallengeId,
        contributorId,
        expectedChallengePurpose
      )
      : null;
    if (!activeChallengeBytes) {
      return res.status(400).json({ error: 'Недійсний або протермінований challenge активної liveness' });
    }
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
  // Device-side метрики — лише App-Attest-підписаний pre-check. У v7
  // рішення ухвалюється заново із сирих DG та кадрів в ізольованому
  // одноразовому self-hosted worker'і. Legacy-протоколи не приймаються.
  const biometric = verificationPolicy.validateBiometricEvidence(body, activeChallengeBytes);
  if (!biometric.ok) return res.status(400).json({ error: biometric.error });
  // Окремий операційний kill switch. Навіть коректно відкалібрований worker
  // не може автоматично видати Verified ID, доки rollout не схвалено явно.
  if (protocolVersion === verificationPolicy.PROTOCOL_VERSION &&
      !evaluationOnly &&
      !verificationPolicy.isSelfHostedVerificationEnabled()) {
    return res.status(503).json({
      error: 'Автоматична верифікація ще не активована. Спробуй пізніше.',
      code: 'SELF_HOSTED_VERIFICATION_DISABLED',
      retryable: true,
    });
  }
  if (typeof sod !== 'string' || sod.length === 0 || sod.length > 96 * 1024) {
    return res.status(400).json({ error: 'SOD відсутній або завеликий' });
  }
  // Строга форма dgHashes: рівно {dg1,dg2}, кожен — обʼєкт
  // {алгоритм → hex}, hex лише [0-9a-f], розумної довжини (F3).
  if (!isValidDgHashes(dgHashes)) {
    return res.status(400).json({ error: 'Недопустима форма dgHashes' });
  }

  let documentChallengeBytes = null;
  if (protocolVersion === verificationPolicy.PROTOCOL_VERSION) {
    if (!['passed', 'not_supported'].includes(chipAuthentication) ||
        !['passed', 'not_supported'].includes(activeAuthentication)) {
      return res.status(400).json({ error: 'Некоректний стан автентифікації чипа' });
    }
    const expectedPurpose = evaluationOnly
      ? 'document_auth_calibration'
      : 'document_auth';
    documentChallengeBytes =
      typeof documentAuthenticationChallengeId === 'string'
        ? appattest.consumeChallenge(
          documentAuthenticationChallengeId,
          contributorId,
          expectedPurpose
        )
        : null;
    if (!documentChallengeBytes) {
      return res.status(400).json({
        error: 'Недійсний або протермінований challenge документа',
        code: 'DOCUMENT_CHALLENGE_INVALID',
      });
    }
  }

  // ── Passive Authentication (ICAO 9303): серверна перевірка SOD ────
  // ОБОВʼЯЗКОВА: немає криптодоказу справжності документа — немає
  // Verified ID. Обходу не існує (dev-bypass фізично видалено).
  let pa;
  let serverBiometrics = null;
  let opaqueEnvelope = null;
  try {
    if (protocolVersion === verificationPolicy.PROTOCOL_VERSION) {
      opaqueEnvelope = parseSelfHostedEnvelope(body.biometricEnvelope);
    }

    pa = await passiveauth.verifySOD({
      sodBase64: sod,
      dgHashes,
    });

    if (pa.status === 'passed' && opaqueEnvelope) {
      serverBiometrics = await biometricClient.verifySelfHostedBiometrics(
        opaqueEnvelope,
        verificationPolicy.deriveSequence(activeChallengeBytes),
        activeChallengeBytes,
        documentChallengeBytes,
        evaluationOnly
      );
      if (serverBiometrics.evaluationOnly !== evaluationOnly) {
        throw new Error('biometric_response_mode_mismatch');
      }
      // The first PA pass avoids running expensive biometrics for an invalid
      // document. The authoritative PA pass below uses hashes computed only
      // after decrypting raw DG1/DG2 inside the one-request worker.
      for (const group of Object.keys(dgHashes)) {
        for (const [algorithm, clientHash] of Object.entries(dgHashes[group])) {
          const workerHash = serverBiometrics.dgHashes?.[group]?.[algorithm];
          if (typeof workerHash !== 'string' || workerHash.length !== clientHash.length ||
              !crypto.timingSafeEqual(Buffer.from(workerHash, 'hex'),
                Buffer.from(clientHash.toLowerCase(), 'hex'))) {
            throw new Error('biometric_envelope_dg_hash_mismatch');
          }
        }
      }
      pa = await passiveauth.verifySOD({
        sodBase64: sod,
        dgHashes: serverBiometrics.dgHashes,
      });
      const documentResult = serverBiometrics.documentAuthentication;
      if (!documentResult ||
          documentResult.chipAuthentication !== chipAuthentication ||
          documentResult.activeAuthentication !== activeAuthentication) {
        throw new Error('biometric_envelope_document_auth_mismatch');
      }
    }
  } catch (e) {
    const validationFailure = typeof e?.message === 'string' &&
      /^(?:biometric_envelope_|ephemeral_public_key_|envelope_nonce_|envelope_ciphertext_)/.test(e.message);
    if (validationFailure) {
      return res.status(400).json({
        error: 'Некоректний або неповний доказ документа/біометрії.',
        code: 'EVIDENCE_INVALID',
      });
    }
    console.error('[verify/approve] self-hosted verifier unavailable:', e?.message || String(e));
    return res.status(503).json({
      error: 'Перевірка біометрії тимчасово недоступна. Спробуй пізніше.',
      code: 'BIOMETRIC_UNAVAILABLE',
      retryable: true,
    });
  } finally {
    // Auth володіє лише ciphertext. Plaintext DG/frames існують виключно в
    // worker max_requests=1, address space якого ОС знищує після відповіді.
    if (Buffer.isBuffer(req.rawBody)) req.rawBody.fill(0);
    if (Buffer.isBuffer(documentChallengeBytes)) documentChallengeBytes.fill(0);
    if (Buffer.isBuffer(activeChallengeBytes)) activeChallengeBytes.fill(0);
    if (body.biometricEnvelope !== undefined) body.biometricEnvelope = null;
  }

  if (pa.status !== 'passed') {
    console.warn(`[verify/approve] PA REJECT ${contributorId.slice(0,8)}… status=${pa.status} reason=${pa.reason}`);
    const msg = pa.status === 'unavailable'
      ? (pa.reason === 'dsc_not_found'
        ? 'Сервер ще не має сертифіката підписанта цього документа. Документ не відхилено; оновлюємо ICAO PKD.'
        : 'Перевірка справжності документа тимчасово недоступна. Спробуй пізніше.')
      : 'Документ не пройшов криптографічну перевірку справжності';
    return res.status(pa.status === 'unavailable' ? 503 : 400).json({
      error: msg,
      code: pa.reason === 'dsc_not_found' ? 'PA_TRUST_MATERIAL_MISSING' : 'PA_FAILED',
      retryable: pa.status === 'unavailable',
    });
  }

  // Shadow/PAD calibration stops here. It performs the full cryptographic
  // document and isolated biometric evaluation, but cannot derive a document
  // token, create a review request or mutate contributors.verified.
  if (evaluationOnly) {
    if (!serverBiometrics || serverBiometrics.evaluationOnly !== true ||
        serverBiometrics.decision === 'unavailable') {
      return res.status(503).json({
        error: 'Тестова перевірка біометрії тимчасово недоступна.',
        code: 'BIOMETRIC_UNAVAILABLE',
        retryable: true,
      });
    }
    console.log(`[verify/approve] ${contributorId.slice(0,8)}… status=calibration ` +
      `decision=${serverBiometrics.decision} reason=${serverBiometrics.reason} ` +
      `provider=self_hosted_v2`);
    // A fully processed allowlisted calibration run is not an authentication
    // failure and cannot activate Verified ID. Clear the ordinary liveness
    // escalation so repeated physical measurements do not lock the tester.
    // The global per-IP middleware still caps request bursts.
    try { for (const key of rlKeysFor(contributorId, req)) await rlReset(key); }
    catch (e) { console.error('[verify/approve] calibration rl_reset:', e.message); }
    return res.json({
      ok: true,
      status: 'calibration',
      reviewRequired: false,
      verified: false,
      evaluationOnly: true,
      passiveAuthentication: 'passed',
      documentAuthentication: serverBiometrics.documentAuthentication,
      decision: serverBiometrics.decision,
      reason: serverBiometrics.reason,
      policyVersion: serverBiometrics.policyVersion,
      modelSetHash: serverBiometrics.modelSetHash,
      metrics: {
        faceMedian: serverBiometrics.faceMedian,
        faceMinimum: serverBiometrics.faceMinimum,
        padMedian: serverBiometrics.padMedian,
        padMinimum: serverBiometrics.padMinimum,
        depthMedianRelief: serverBiometrics.depthMedianRelief,
        depthValidFraction: serverBiometrics.depthValidFraction,
        depthPassed: serverBiometrics.depthPassed,
        challengePassed: serverBiometrics.challengePassed,
      },
      calibrationSignals: serverBiometrics.calibrationSignals,
    });
  }


  if (protocolVersion === verificationPolicy.PROTOCOL_VERSION) {
    if (!serverBiometrics || serverBiometrics.decision === 'unavailable') {
      return res.status(503).json({
        error: 'Перевірка біометрії тимчасово недоступна. Спробуй пізніше.',
        code: 'BIOMETRIC_UNAVAILABLE',
        retryable: true,
      });
    }
    if (serverBiometrics.decision !== 'passed') {
      return res.status(400).json({
        error: 'Не вдалося підтвердити живу присутність і збіг обличчя.',
        code: 'BIOMETRIC_FAILED',
        retryable: true,
      });
    }
  }

  const documentAssurance =
    serverBiometrics?.documentAuthentication?.assurance || 'passive_only';
  const automaticDocumentAssurance =
    documentAssurance === 'active_authentication';

  // ── «Один документ = один акаунт» + бан документа ────────────────
  // token = HMAC(pepper, держ. хеш DG1 із SOD): односторонній,
  // детермінований. Номер паспорта НЕ зберігається і не відновлюється.
  const DOC_PEPPER = process.env.DOC_TOKEN_PEPPER || '';
  const LEGACY_DOC_PEPPER = process.env.DOC_TOKEN_PEPPER_PREVIOUS || '';
  if (!DOC_PEPPER) {
    console.error('[verify/approve] DOC_TOKEN_PEPPER відсутній — верифікація зупинена (fail-closed)');
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }
  const docToken = crypto.createHmac('sha256', DOC_PEPPER)
    .update('doc-token-v1:' + pa.sodDG1Hash).digest('hex');
  const legacyDocToken = LEGACY_DOC_PEPPER && LEGACY_DOC_PEPPER !== DOC_PEPPER
    ? crypto.createHmac('sha256', LEGACY_DOC_PEPPER)
        .update('doc-token-v1:' + pa.sodDG1Hash).digest('hex')
    : null;

  const level = automaticDocumentAssurance
    ? 'document_active'
    : 'document_passive';
  const b = biometric.normalized;

  // БЕЗПЕКА ПЕРШ ЗА ВСЕ (raw SQL): суворо валідуємо КОЖНЕ значення, що
  // йде в SQL-рядок. Інʼєкція неможлива — лише hex/uuid/whitelist.
  if (!/^[0-9a-f]{64}$/.test(docToken) ||
      (legacyDocToken !== null && !/^[0-9a-f]{64}$/.test(legacyDocToken)) ||
      !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(contributorId) ||
      !['passive_only', 'chip_authentication_attested', 'active_authentication']
        .includes(documentAssurance) ||
      !['document_active', 'document_passive'].includes(level)) {
    console.error('[verify/approve] bind params failed validation (fail-closed)');
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }

  try {
    if (protocolVersion === verificationPolicy.PROTOCOL_VERSION &&
        automaticDocumentAssurance) {
      const receipt = serverBiometrics;
      if (!receipt ||
          receipt.evaluationOnly !== false ||
          !/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(receipt.requestId) ||
          !/^[a-zA-Z0-9_.-]{8,100}$/.test(receipt.policyVersion) ||
          !/^[0-9a-f]{64}$/.test(receipt.modelSetHash) ||
          !/^[0-9a-f]{64}$/.test(receipt.receiptDigest) ||
          !/^[0-9a-f]{64}$/.test(receipt.receiptSignature) ||
          !Number.isInteger(receipt.receiptTimestamp)) {
        console.error('[verify/approve] invalid self-hosted receipt (fail-closed)');
        return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
      }
      const result = await db.pool.query(
        `SELECT activate_self_hosted_verified_id_v7_rotating(
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
         ) AS outcome`,
        [
          docToken, legacyDocToken, contributorId, receipt.requestId,
          receipt.policyVersion, receipt.modelSetHash, receipt.receiptDigest,
          receipt.receiptSignature, receipt.receiptTimestamp, protocolVersion,
          documentAssurance,
        ]
      );
      const outcome = result.rows?.[0]?.outcome;
      if (outcome === 'banned') {
        return res.status(403).json({ error: 'Цей документ заблоковано за порушення правил спільноти.' });
      }
      if (outcome === 'duplicate') {
        return res.status(409).json({ error: 'Цей документ уже використано для верифікації іншого акаунта.' });
      }
      if (outcome === 'contributor_conflict' || outcome === 'conflict') {
        return res.status(409).json({ error: 'Для цього акаунта або документа вже є інша активна верифікація.' });
      }
      if (outcome === 'already_verified') {
        return res.status(409).json({ error: 'Цей акаунт уже верифіковано.' });
      }
      if (outcome !== 'verified') {
        console.error('[verify/approve] activate_self_hosted_verified_id_v7_rotating → ', outcome);
        return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
      }

      console.log(`[verify/approve] ${contributorId.slice(0,8)}… status=verified level=strong pa=passed provider=self_hosted_v2`);
      try { for (const key of rlKeysFor(contributorId, req)) await rlReset(key); }
      catch (e) { console.error('[verify/approve] rl_reset:', e.message); }
      if (session) {
        const s = getVerifySession(session);
        if (s && s.contributorId === contributorId) s.status = 'verified';
      }
      return res.json({
        ok: true,
        status: 'verified',
        reviewRequired: false,
        verified: true,
        level: 'strong',
        passiveAuthentication: pa.status,
      });
    }

    // ОДНА транзакційна функція резервує document token у review-черзі,
    // перевіряє ban/duplicate і НЕ змінює contributors.verified.
    const result = await db.pool.query(
      `SELECT submit_verification_review_v7_rotating(
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
       ) AS outcome`,
      [
        docToken, legacyDocToken, contributorId, b.faceModel,
        b.faceModelVersion, b.faceScore, b.faceThreshold, b.faceSampleCount,
        b.faceContinuityScore, b.livenessFrameCount, b.livenessDurationMs,
        b.protocolVersion, documentAssurance,
      ]
    );
    const outcome = result.rows?.[0]?.outcome;

    if (outcome === 'banned') {
      console.warn(`[verify/approve] BANNED DOC ${contributorId.slice(0,8)}…`);
      return res.status(403).json({ error: 'Цей документ заблоковано за порушення правил спільноти.' });
    }
    if (outcome === 'duplicate') {
      console.warn(`[verify/approve] DUPLICATE DOC ${contributorId.slice(0,8)}…`);
      return res.status(409).json({ error: 'Цей документ уже використано для верифікації іншого акаунта.' });
    }
    if (outcome === 'contributor_conflict' || outcome === 'conflict') {
      return res.status(409).json({ error: 'Для цього акаунта вже є активна заявка на перевірку.' });
    }
    if (outcome === 'already_verified') {
      return res.status(409).json({ error: 'Цей акаунт уже верифіковано.' });
    }
    if (outcome !== 'pending') {
      console.error('[verify/approve] submit_verification_review_v7_rotating → ', outcome);
      return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
    }

    console.log(`[verify/approve] ${contributorId.slice(0,8)}… status=pending_review level=${level} pa=passed alg=${pa.algorithm || '-'} live=${liveness} issuer_ok=1`);
    // PA + device pre-check прийняті — чистий старт лічильника спроб.
    try { for (const key of rlKeysFor(contributorId, req)) await rlReset(key); }
    catch (e) { console.error('[verify/approve] rl_reset:', e.message); }
    // Якщо флоу стартував з десктопа через QR — повідомити його модалку.
    if (session) {
      const s = getVerifySession(session);
      if (s && s.contributorId === contributorId) s.status = 'pending_review';
    }
    return res.json({
      ok: true,
      status: 'pending_review',
      reviewRequired: true,
      verified: false,
      level,
      passiveAuthentication: pa.status,
    });
  } catch (e) {
    console.error('[verify/approve] submit_verification_review_v7_rotating (run_sql):', e.message);
    return res.status(503).json({ error: 'Верифікація тимчасово недоступна. Спробуй пізніше.' });
  }
});

// END PROTOCOL V7 VERIFICATION ROUTES
