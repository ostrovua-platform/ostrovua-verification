'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const {
  loadConfiguration,
  loadEnvelopePublicKey,
  signRequest,
  validateResult,
  verifySelfHostedBiometrics,
} = require('../biometric_client');

function result(requestId, evaluationOnly = false) {
  return {
    contract: 'self-hosted-result-v2',
    requestId,
    decision: 'passed',
    reason: 'passed',
    policyVersion: 'ostrovua-self-hosted-2026-07-v2',
    modelSetHash: 'a'.repeat(64),
    faceMedian: 0.61,
    faceMinimum: 0.55,
    padMedian: 0.93,
    padMinimum: 0.82,
    depthMedianRelief: 0.021,
    depthValidFraction: 0.98,
    depthPassed: true,
    challengePassed: true,
    evaluationOnly,
    calibrationSignals: evaluationOnly ? {
      neutralFaceScores: [0.61, 0.60, 0.59],
      challengeFaceScores: Array(12).fill(0.58),
      padScores: Array(12).fill(0.93),
      qualityPassed: true,
      depthPassed: true,
      challengePassed: true,
    } : null,
    dgHashes: {
      dg1: {
        sha1: '1'.repeat(40), sha224: '2'.repeat(56), sha256: '3'.repeat(64),
        sha384: '4'.repeat(96), sha512: '5'.repeat(128),
      },
      dg2: {
        sha1: '6'.repeat(40), sha224: '7'.repeat(56), sha256: '8'.repeat(64),
        sha384: '9'.repeat(96), sha512: 'a'.repeat(128),
      },
      dg15: {
        sha1: 'b'.repeat(40), sha224: 'c'.repeat(56), sha256: 'd'.repeat(64),
        sha384: 'e'.repeat(96), sha512: 'f'.repeat(128),
      },
    },
    documentAuthentication: {
      assurance: 'active_authentication',
      activeAuthentication: 'passed',
      chipAuthentication: 'not_supported',
      activeAuthenticationMethod: 'ecdsa-sha256',
    },
  };
}

test('request signature binds timestamp, nonce and exact body', () => {
  const secret = Buffer.alloc(32, 7);
  const body = Buffer.from('{"x":1}');
  const first = signRequest(secret, '1780000000', '0'.repeat(32), body);
  assert.match(first, /^[0-9a-f]{64}$/);
  assert.notEqual(first, signRequest(secret, '1780000000', '1'.repeat(32), body));
  assert.notEqual(first, signRequest(secret, '1780000000', '0'.repeat(32), Buffer.from('{"x":2}')));
});

test('production biometric public key must match its trusted pin', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ostrovua-key-pin-'));
  const keyPath = path.join(directory, 'public.key');
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyPath, key, { mode: 0o600 });
  const keyId = crypto.createHash('sha256').update(key).digest('hex');
  const previous = {
    appEnv: process.env.APP_ENV,
    keyPath: process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE,
    pin: process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256,
  };
  process.env.APP_ENV = 'production';
  process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE = keyPath;
  process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256 = keyId;
  try {
    assert.equal(loadEnvelopePublicKey().keyId, keyId);
    process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256 = '0'.repeat(64);
    assert.throws(
      () => loadEnvelopePublicKey(),
      /biometric_envelope_public_key_pin_mismatch/
    );
  } finally {
    process.env.APP_ENV = previous.appEnv;
    process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE = previous.keyPath;
    process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_SHA256 = previous.pin;
    key.fill(0);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('result validator rejects a passed decision without active challenge', () => {
  const payload = result(crypto.randomUUID());
  payload.challengePassed = false;
  assert.throws(() => validateResult(payload, payload.requestId), /biometric_response_invalid/);
});

test('result validator requires the signed evaluation-only mode bit', () => {
  const payload = result(crypto.randomUUID());
  delete payload.evaluationOnly;
  assert.throws(() => validateResult(payload, payload.requestId), /biometric_response_invalid/);
});

test('production result cannot disclose calibration score series', () => {
  const payload = result(crypto.randomUUID());
  payload.calibrationSignals = result(crypto.randomUUID(), true).calibrationSignals;
  assert.throws(() => validateResult(payload, payload.requestId), /biometric_response_invalid/);
});

test('evaluation-only result requires complete transaction score series', () => {
  const payload = result(crypto.randomUUID(), true);
  payload.calibrationSignals.padScores.pop();
  assert.throws(() => validateResult(payload, payload.requestId), /biometric_response_invalid/);
});

test('result validator accepts policy failure reasons in lowercase snake case', () => {
  const payload = result(crypto.randomUUID(), true);
  payload.decision = 'failed';
  payload.reason = 'challenge_turn_left_missing';
  payload.challengePassed = false;
  payload.calibrationSignals.challengePassed = false;
  assert.equal(validateResult(payload, payload.requestId).reason, payload.reason);
});

test('client accepts only an HMAC-signed response for the same request id', async () => {
  const secret = crypto.randomBytes(32);
  let sawValidRequestSignature = false;
  let sawOnlyOpaqueEvidence = false;
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks);
      const timestamp = request.headers['x-biometric-timestamp'];
      const nonce = request.headers['x-biometric-nonce'];
      sawValidRequestSignature = request.headers['x-biometric-signature'] ===
        signRequest(secret, timestamp, nonce, body);
      const requestPayload = JSON.parse(body);
      const requestId = requestPayload.requestId;
      sawOnlyOpaqueEvidence = requestPayload.contract === 'self-hosted-forward-v2' &&
        requestPayload.envelope?.contract === 'self-hosted-envelope-v3' &&
        typeof requestPayload.documentChallenge === 'string' &&
        requestPayload.evaluationOnly === false &&
        requestPayload.dg2Face === undefined && requestPayload.rawDataGroups === undefined;
      const responseBody = Buffer.from(JSON.stringify(result(requestId)));
      const responseTimestamp = String(Math.floor(Date.now() / 1000));
      const digest = crypto.createHash('sha256').update(responseBody).digest('hex');
      const signature = crypto.createHmac('sha256', secret)
        .update(`v1\n${requestId}\n${responseTimestamp}\n${digest}`, 'ascii').digest('hex');
      response.writeHead(200, {
        'content-type': 'application/json',
        'x-biometric-timestamp': responseTimestamp,
        'x-biometric-signature': signature,
      });
      response.end(responseBody);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const previous = {
    enabled: process.env.SELF_HOSTED_VERIFICATION_ENABLED,
    url: process.env.BIOMETRIC_SERVICE_URL,
    secret: process.env.BIOMETRIC_HMAC_SECRET,
  };
  process.env.SELF_HOSTED_VERIFICATION_ENABLED = '1';
  process.env.BIOMETRIC_SERVICE_URL = `http://127.0.0.1:${address.port}/v1/verify`;
  process.env.BIOMETRIC_HMAC_SECRET = secret.toString('base64');
  try {
    const response = await verifySelfHostedBiometrics({
      contract: 'self-hosted-envelope-v3',
      keyId: 'b'.repeat(64),
      ephemeralPublicKey: Buffer.alloc(32, 1).toString('base64'),
      nonce: Buffer.alloc(12, 2).toString('base64'),
      ciphertext: Buffer.alloc(128, 3).toString('base64'),
    }, ['turnLeft', 'blink'], Buffer.alloc(32, 4), Buffer.alloc(32, 5));
    assert.equal(response.decision, 'passed');
    assert.match(response.receiptDigest, /^[0-9a-f]{64}$/);
    assert.match(response.receiptSignature, /^[0-9a-f]{64}$/);
    assert.equal(Number.isInteger(response.receiptTimestamp), true);
    assert.equal(sawValidRequestSignature, true);
    assert.equal(sawOnlyOpaqueEvidence, true);
  } finally {
    process.env.SELF_HOSTED_VERIFICATION_ENABLED = previous.enabled;
    process.env.BIOMETRIC_SERVICE_URL = previous.url;
    process.env.BIOMETRIC_HMAC_SECRET = previous.secret;
    await new Promise((resolve) => server.close(resolve));
  }
});

test('shadow configuration is independent from the production activation switch', () => {
  const secret = crypto.randomBytes(32).toString('base64');
  const previous = {
    enabled: process.env.SELF_HOSTED_VERIFICATION_ENABLED,
    shadow: process.env.BIOMETRIC_SHADOW_MODE_ENABLED,
    url: process.env.BIOMETRIC_SERVICE_URL,
    secret: process.env.BIOMETRIC_HMAC_SECRET,
  };
  process.env.SELF_HOSTED_VERIFICATION_ENABLED = '0';
  process.env.BIOMETRIC_SHADOW_MODE_ENABLED = '1';
  process.env.BIOMETRIC_SERVICE_URL = 'http://biometric:8080/v1/verify';
  process.env.BIOMETRIC_HMAC_SECRET = secret;
  try {
    const configuration = loadConfiguration(true);
    assert.equal(configuration.url, 'http://biometric:8080/v1/verify');
    configuration.secret.fill(0);
    assert.throws(() => loadConfiguration(false), /self_hosted_disabled/);
  } finally {
    process.env.SELF_HOSTED_VERIFICATION_ENABLED = previous.enabled;
    process.env.BIOMETRIC_SHADOW_MODE_ENABLED = previous.shadow;
    process.env.BIOMETRIC_SERVICE_URL = previous.url;
    process.env.BIOMETRIC_HMAC_SECRET = previous.secret;
  }
});
