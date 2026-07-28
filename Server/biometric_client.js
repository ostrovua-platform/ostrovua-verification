'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fetchImpl = globalThis.fetch || require('node-fetch');

const RESPONSE_KEYS = [
  'contract', 'requestId', 'decision', 'reason', 'policyVersion',
  'modelSetHash', 'faceMedian', 'faceMinimum', 'padMedian', 'padMinimum',
  'depthMedianRelief', 'depthValidFraction', 'depthPassed',
  'challengePassed', 'dgHashes', 'documentAuthentication', 'evaluationOnly',
  'calibrationSignals',
];
const CALIBRATION_SIGNAL_KEYS = [
  'neutralFaceScores', 'challengeFaceScores', 'padScores',
  'qualityPassed', 'depthPassed', 'challengePassed',
];
const DG_HEX_LENGTHS = { sha1: 40, sha224: 56, sha256: 64, sha384: 96, sha512: 128 };

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function loadConfiguration(evaluationOnly = false) {
  if (typeof evaluationOnly !== 'boolean') {
    throw new Error('biometric_evaluation_mode_invalid');
  }
  if (evaluationOnly) {
    if (process.env.BIOMETRIC_SHADOW_MODE_ENABLED !== '1') {
      throw new Error('biometric_shadow_disabled');
    }
  } else if (process.env.SELF_HOSTED_VERIFICATION_ENABLED !== '1') {
    throw new Error('self_hosted_disabled');
  }
  const url = process.env.BIOMETRIC_SERVICE_URL || '';
  if (!/^http:\/\/[a-zA-Z0-9_.-]+(?::[0-9]{2,5})?\/v1\/verify$/.test(url)) {
    throw new Error('biometric_service_url_invalid');
  }
  const secretPath = process.env.BIOMETRIC_HMAC_SECRET_FILE || '';
  let secret;
  if (secretPath) {
    try { secret = fs.readFileSync(secretPath); }
    catch { throw new Error('biometric_secret_file_unavailable'); }
  } else {
    if ((process.env.APP_ENV || process.env.NODE_ENV) === 'production') {
      throw new Error('biometric_secret_file_required');
    }
    const encoded = process.env.BIOMETRIC_HMAC_SECRET || '';
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
      throw new Error('biometric_secret_invalid');
    }
    secret = Buffer.from(encoded, 'base64');
    if (secret.toString('base64') !== encoded) {
      secret.fill(0);
      throw new Error('biometric_secret_invalid');
    }
  }
  if (secret.length !== 32) {
    secret.fill(0);
    throw new Error('biometric_secret_invalid');
  }
  return { url, secret };
}

function loadEnvelopePublicKey() {
  const path = process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE ||
    '/app/certs/biometric_envelope_public.key';
  let raw;
  try { raw = fs.readFileSync(path); }
  catch { throw new Error('biometric_envelope_public_key_missing'); }
  if (raw.length !== 32) {
    raw.fill(0);
    throw new Error('biometric_envelope_public_key_invalid');
  }
  const keyId = crypto.createHash('sha256').update(raw).digest('hex');
  const expectedKeyId = process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256 || '';
  const production = (process.env.APP_ENV || process.env.NODE_ENV) === 'production';
  if ((production && !/^[0-9a-f]{64}$/.test(expectedKeyId)) ||
      (expectedKeyId && expectedKeyId !== keyId)) {
    raw.fill(0);
    throw new Error('biometric_envelope_public_key_pin_mismatch');
  }
  const result = { keyId, publicKey: raw.toString('base64') };
  raw.fill(0);
  return result;
}

function signRequest(secret, timestamp, nonce, body) {
  const digest = crypto.createHash('sha256').update(body).digest('hex');
  return crypto.createHmac('sha256', secret)
    .update(`v1\n${timestamp}\n${nonce}\n${digest}`, 'ascii')
    .digest('hex');
}

function verifyResponseSignature(secret, requestId, body, headers) {
  const timestamp = headers.get('x-biometric-timestamp') || '';
  const signature = headers.get('x-biometric-signature') || '';
  if (!/^\d{10}$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 30 ||
      !/^[0-9a-f]{64}$/.test(signature)) return false;
  const digest = crypto.createHash('sha256').update(body).digest('hex');
  const expected = crypto.createHmac('sha256', secret)
    .update(`v1\n${requestId}\n${timestamp}\n${digest}`, 'ascii')
    .digest();
  return crypto.timingSafeEqual(expected, Buffer.from(signature, 'hex'));
}

function receiptMetadata(body, headers) {
  const timestamp = headers.get('x-biometric-timestamp') || '';
  const signature = headers.get('x-biometric-signature') || '';
  if (!/^\d{10}$/.test(timestamp) || !/^[0-9a-f]{64}$/.test(signature)) {
    throw new Error('biometric_receipt_invalid');
  }
  return {
    receiptDigest: crypto.createHash('sha256').update(body).digest('hex'),
    receiptSignature: signature,
    receiptTimestamp: Number(timestamp),
  };
}

function validateResult(result, requestId) {
  if (!exactKeys(result, RESPONSE_KEYS) || result.contract !== 'self-hosted-result-v2' ||
      result.requestId !== requestId || !['passed', 'failed', 'unavailable'].includes(result.decision) ||
      typeof result.reason !== 'string' || !/^[a-z0-9_]{1,80}$/.test(result.reason) ||
      typeof result.policyVersion !== 'string' || !/^[a-zA-Z0-9_.-]{8,100}$/.test(result.policyVersion) ||
      typeof result.modelSetHash !== 'string' || !/^[0-9a-f]{64}$/.test(result.modelSetHash) ||
      typeof result.depthPassed !== 'boolean' ||
      typeof result.challengePassed !== 'boolean' || typeof result.evaluationOnly !== 'boolean') {
    throw new Error('biometric_response_invalid');
  }
  if (!result.evaluationOnly) {
    if (result.calibrationSignals !== null) {
      throw new Error('biometric_response_invalid');
    }
  } else {
    const signals = result.calibrationSignals;
    if (!exactKeys(signals, CALIBRATION_SIGNAL_KEYS) ||
        typeof signals.qualityPassed !== 'boolean' ||
        typeof signals.depthPassed !== 'boolean' ||
        typeof signals.challengePassed !== 'boolean' ||
        signals.depthPassed !== result.depthPassed ||
        signals.challengePassed !== result.challengePassed) {
      throw new Error('biometric_response_invalid');
    }
    const series = [
      [signals.neutralFaceScores, 3, 5, -1, 1],
      [signals.challengeFaceScores, 12, 24, -1, 1],
      [signals.padScores, 12, 24, 0, 1],
    ];
    for (const [values, minimum, maximum, low, high] of series) {
      if (!Array.isArray(values) || values.length < minimum || values.length > maximum ||
          values.some((value) => typeof value !== 'number' || !Number.isFinite(value) ||
            value < low || value > high)) {
        throw new Error('biometric_response_invalid');
      }
    }
    if (signals.challengeFaceScores.length !== signals.padScores.length) {
      throw new Error('biometric_response_invalid');
    }
  }
  const groupNames = Object.keys(result.dgHashes || {}).sort();
  if (!groupNames.includes('dg1') || !groupNames.includes('dg2') ||
      groupNames.some((group) => !['dg1', 'dg2', 'dg14', 'dg15'].includes(group))) {
    throw new Error('biometric_response_invalid');
  }
  for (const group of groupNames) {
    if (!exactKeys(result.dgHashes[group], Object.keys(DG_HEX_LENGTHS))) {
      throw new Error('biometric_response_invalid');
    }
    for (const [algorithm, length] of Object.entries(DG_HEX_LENGTHS)) {
      const value = result.dgHashes[group][algorithm];
      if (typeof value !== 'string' || value.length !== length || !/^[0-9a-f]+$/.test(value)) {
        throw new Error('biometric_response_invalid');
      }
    }
  }
  const documentAuthentication = result.documentAuthentication;
  if (!exactKeys(documentAuthentication, [
    'assurance', 'activeAuthentication', 'chipAuthentication',
    'activeAuthenticationMethod',
  ]) ||
      !['passive_only', 'chip_authentication_attested', 'active_authentication']
        .includes(documentAuthentication.assurance) ||
      !['passed', 'not_supported'].includes(documentAuthentication.activeAuthentication) ||
      !['passed', 'not_supported'].includes(documentAuthentication.chipAuthentication) ||
      typeof documentAuthentication.activeAuthenticationMethod !== 'string' ||
      !/^(?:none|(?:ecdsa|rsa)-(?:sha1|sha224|sha256|sha384|sha512))$/
        .test(documentAuthentication.activeAuthenticationMethod) ||
      (documentAuthentication.assurance === 'active_authentication') !==
        (documentAuthentication.activeAuthentication === 'passed') ||
      (documentAuthentication.activeAuthentication === 'passed') !==
        (documentAuthentication.activeAuthenticationMethod !== 'none') ||
      (documentAuthentication.assurance === 'chip_authentication_attested' &&
        documentAuthentication.chipAuthentication !== 'passed') ||
      (documentAuthentication.chipAuthentication === 'passed' &&
        !groupNames.includes('dg14')) ||
      (documentAuthentication.assurance === 'chip_authentication_attested' &&
        !groupNames.includes('dg14')) ||
      (groupNames.includes('dg15') !==
        (documentAuthentication.activeAuthentication === 'passed'))) {
    throw new Error('biometric_response_invalid');
  }
  for (const field of ['faceMedian', 'faceMinimum', 'padMedian', 'padMinimum']) {
    if (typeof result[field] !== 'number' || !Number.isFinite(result[field]) ||
        result[field] < -1 || result[field] > 1) {
      throw new Error('biometric_response_invalid');
    }
  }
  if (typeof result.depthMedianRelief !== 'number' ||
      !Number.isFinite(result.depthMedianRelief) ||
      result.depthMedianRelief < -0.1 || result.depthMedianRelief > 0.1 ||
      typeof result.depthValidFraction !== 'number' ||
      !Number.isFinite(result.depthValidFraction) ||
      result.depthValidFraction < 0 || result.depthValidFraction > 1) {
    throw new Error('biometric_response_invalid');
  }
  if (result.decision === 'passed' && (!result.challengePassed || result.reason !== 'passed')) {
    throw new Error('biometric_response_invalid');
  }
  return result;
}

async function verifySelfHostedBiometrics(
  envelope, expectedActions, challengeBytes, documentChallengeBytes,
  evaluationOnly = false
) {
  const { url, secret } = loadConfiguration(evaluationOnly);
  let body;
  let responseBody;
  try {
    if (!envelope || !Buffer.isBuffer(challengeBytes) || challengeBytes.length !== 32 ||
        !Buffer.isBuffer(documentChallengeBytes) ||
        documentChallengeBytes.length !== 32 ||
        !Array.isArray(expectedActions) || expectedActions.length !== 2 ||
        expectedActions.some((action) => !['turnLeft', 'turnRight', 'blink'].includes(action))) {
      throw new Error('biometric_request_invalid');
    }
    const requestId = crypto.randomUUID();
    body = Buffer.from(JSON.stringify({
      contract: 'self-hosted-forward-v2',
      requestId,
      expectedActions,
      challenge: challengeBytes.toString('base64'),
      documentChallenge: documentChallengeBytes.toString('base64'),
      envelope,
      evaluationOnly,
    }), 'utf8');
    if (body.length > 12 * 1024 * 1024) throw new Error('biometric_request_oversized');

    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = crypto.randomBytes(16).toString('hex');
    const signature = signRequest(secret, timestamp, nonce, body);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 40_000);
    let response;
    try {
      response = await fetchImpl(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(body.length),
          'x-biometric-timestamp': timestamp,
          'x-biometric-nonce': nonce,
          'x-biometric-signature': signature,
        },
        body,
        signal: controller.signal,
        size: 64 * 1024,
      });
      const declaredLength = Number(response.headers.get('content-length') || '0');
      if (declaredLength > 64 * 1024) throw new Error('biometric_response_oversized');
      responseBody = Buffer.from(await response.arrayBuffer());
      if (responseBody.length > 64 * 1024) throw new Error('biometric_response_oversized');
    } finally {
      clearTimeout(timer);
    }
    if (!verifyResponseSignature(secret, requestId, responseBody, response.headers)) {
      throw new Error('biometric_response_signature_invalid');
    }
    if (response.status !== 200) throw new Error('biometric_service_rejected');
    let result;
    try { result = JSON.parse(responseBody.toString('utf8')); }
    catch { throw new Error('biometric_response_invalid'); }
    const validated = validateResult(result, requestId);
    if (validated.evaluationOnly !== evaluationOnly) {
      throw new Error('biometric_response_mode_mismatch');
    }
    return {
      ...validated,
      ...receiptMetadata(responseBody, response.headers),
    };
  } finally {
    if (body) body.fill(0);
    if (responseBody) responseBody.fill(0);
    secret.fill(0);
  }
}

module.exports = {
  loadConfiguration,
  loadEnvelopePublicKey,
  signRequest,
  verifyResponseSignature,
  receiptMetadata,
  validateResult,
  verifySelfHostedBiometrics,
};
