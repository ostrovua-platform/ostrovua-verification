'use strict';

const crypto = require('crypto');

const PROTOCOL_VERSION = 7;
const FACE_MODEL = 'coreml';
const FACE_MODEL_VERSION = 'facenet-vggface2-coreml-04a4db780288799e';
const FACE_THRESHOLD = 0.50;
const CONTINUITY_THRESHOLD = 0.40;
const ACTIONS = ['turnLeft', 'turnRight', 'blink'];

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function deriveSequence(seed, length = 2) {
  if (!Buffer.isBuffer(seed) || seed.length < 16) throw new Error('invalid challenge seed');
  const sequence = [];
  let counter = 0;
  let last = null;
  while (sequence.length < length) {
    const digest = crypto.createHash('sha256')
      .update(seed)
      .update(Buffer.from([counter & 0xff]))
      .digest();
    counter = (counter + 1) & 0xff;
    const action = ACTIONS[digest[0] % ACTIONS.length];
    if (action !== last) {
      sequence.push(action);
      last = action;
    }
  }
  return sequence;
}

function sequenceFingerprint(seed) {
  const canonical = deriveSequence(seed).join(',');
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function exactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function isSelfHostedVerificationEnabled(value = process.env.SELF_HOSTED_VERIFICATION_ENABLED) {
  return value === '1';
}

function isBiometricShadowAllowed(
  contributorId,
  enabled = process.env.BIOMETRIC_SHADOW_MODE_ENABLED,
  testerIds = process.env.BIOMETRIC_SHADOW_TESTER_IDS,
) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  if (enabled !== '1' || typeof contributorId !== 'string' || !uuid.test(contributorId.toLowerCase()) ||
      typeof testerIds !== 'string' || testerIds.length > 4096) return false;
  const values = testerIds.split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
  // Misconfigured allowlists fail closed as a whole; invalid entries are not ignored.
  if (values.length === 0 || values.length > 50 || values.some((value) => !uuid.test(value))) {
    return false;
  }
  return new Set(values).has(contributorId.toLowerCase());
}

/**
 * Перевіряє лише device-attested pre-check evidence. Це навмисно НЕ
 * називається server-side face match: сервер не отримує біометричні
 * зображення/ембеддінги і тому після цієї перевірки дозволений лише review.
 */
function validateBiometricEvidence(body, activeChallengeBytes) {
  if (body.protocolVersion !== PROTOCOL_VERSION) {
    return { ok: false, error: 'Застаріла версія застосунку. Онови OstrovUA.' };
  }
  if (body.liveness !== 'active' || body.activeLiveness !== 'passed') {
    return { ok: false, error: 'Активну перевірку присутності не пройдено' };
  }
  if (body.faceMatch !== 'passed' || body.faceModel !== FACE_MODEL ||
      body.faceModelVersion !== FACE_MODEL_VERSION) {
    return { ok: false, error: 'Непідтримувана модель звірки обличчя' };
  }
  if (!isFiniteNumber(body.faceMatchScore) || body.faceMatchScore < -1 || body.faceMatchScore > 1 ||
      !isFiniteNumber(body.faceMatchThreshold) ||
      Math.abs(body.faceMatchThreshold - FACE_THRESHOLD) > 1e-9 ||
      body.faceMatchScore < body.faceMatchThreshold) {
    return { ok: false, error: 'Результат звірки обличчя не пройшов політику' };
  }
  if (!Number.isInteger(body.faceSampleCount) || body.faceSampleCount < 3 || body.faceSampleCount > 5 ||
      !isFiniteNumber(body.faceContinuityScore) ||
      body.faceContinuityScore < CONTINUITY_THRESHOLD || body.faceContinuityScore > 1) {
    return { ok: false, error: 'Недостатньо стабільних кадрів одного обличчя' };
  }

  const metrics = body.activeLivenessEvidence;
  const metricKeys = [
    'sequenceHash', 'frameCount', 'faceSampleCount', 'durationMs',
    'completedActions', 'multipleFaceFrames',
  ];
  if (!exactKeys(metrics, metricKeys) ||
      typeof metrics.sequenceHash !== 'string' || !/^[0-9a-f]{64}$/.test(metrics.sequenceHash) ||
      !Number.isInteger(metrics.frameCount) || metrics.frameCount < 8 || metrics.frameCount > 3000 ||
      !Number.isInteger(metrics.faceSampleCount) || metrics.faceSampleCount !== body.faceSampleCount ||
      !Number.isInteger(metrics.durationMs) || metrics.durationMs < 500 || metrics.durationMs > 30000 ||
      metrics.completedActions !== 2 || metrics.multipleFaceFrames !== 0) {
    return { ok: false, error: 'Некоректний доказ активної присутності' };
  }
  if (!Buffer.isBuffer(activeChallengeBytes) ||
      metrics.sequenceHash !== sequenceFingerprint(activeChallengeBytes)) {
    return { ok: false, error: 'Liveness evidence не відповідає виданому challenge' };
  }

  return {
    ok: true,
    normalized: {
      protocolVersion: body.protocolVersion,
      faceModel: FACE_MODEL,
      faceModelVersion: FACE_MODEL_VERSION,
      faceScore: body.faceMatchScore,
      faceThreshold: FACE_THRESHOLD,
      faceSampleCount: body.faceSampleCount,
      faceContinuityScore: body.faceContinuityScore,
      livenessMethod: 'active',
      livenessFrameCount: metrics.frameCount,
      livenessDurationMs: metrics.durationMs,
    },
  };
}

module.exports = {
  PROTOCOL_VERSION,
  FACE_MODEL_VERSION,
  deriveSequence,
  sequenceFingerprint,
  isSelfHostedVerificationEnabled,
  isBiometricShadowAllowed,
  validateBiometricEvidence,
};
