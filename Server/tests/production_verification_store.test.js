'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createProductionVerificationStore,
} = require('../production_verification_store');

const UUID_A = '00000000-0000-4000-8000-000000000001';
const UUID_B = '10000000-0000-4000-8000-000000000001';

test('rate-limit adapter is fail-closed for malformed keys and rows', async () => {
  const store = createProductionVerificationStore(async () => [['f', null, '0']]);
  await assert.rejects(() => store.rateLimit('rl_touch', "acct:x'); DROP TABLE contributors;--"));
  await assert.rejects(() => store.rateLimit('unknown', `acct:${UUID_A}`));

  const broken = createProductionVerificationStore(async () => []);
  await assert.rejects(() => broken.rateLimit('rl_check', `acct:${UUID_A}`));
});

test('v7 activation is a fixed, typed SECURITY DEFINER invocation', async () => {
  let observed = '';
  const store = createProductionVerificationStore(async (sql) => {
    observed = sql;
    return [['verified']];
  });
  const outcome = await store.activateSelfHostedV7({
    documentToken: 'a'.repeat(64),
    legacyDocumentToken: null,
    contributorId: UUID_A,
    requestId: UUID_B,
    policyVersion: 'ostrovua-self-hosted-2026-07-v1',
    modelSetHash: 'b'.repeat(64),
    receiptDigest: 'c'.repeat(64),
    receiptSignature: 'd'.repeat(64),
    serviceTimestamp: 1_784_929_000,
    protocolVersion: 7,
    documentAssurance: 'active_authentication',
  });
  assert.equal(outcome, 'verified');
  assert.match(observed, /^SELECT activate_self_hosted_verified_id_v7_rotating\(/);
  assert.match(observed, /NULL::text/);
  assert.doesNotMatch(observed, /\$[0-9]+/);
});

test('server-owned CA activation binds App Attest, challenge and DG14 digest', async () => {
  let observed = '';
  const store = createProductionVerificationStore(async (sql) => {
    observed = sql;
    return [['verified']];
  });
  const outcome = await store.activateSelfHostedCAV7({
    documentToken: 'a'.repeat(64),
    legacyDocumentToken: null,
    contributorId: UUID_A,
    requestId: UUID_B,
    policyVersion: 'ostrovua-self-hosted-2026-07-v1',
    modelSetHash: 'b'.repeat(64),
    receiptDigest: 'c'.repeat(64),
    receiptSignature: 'd'.repeat(64),
    serviceTimestamp: 1_784_929_000,
    protocolVersion: 7,
    documentAssurance: 'chip_authentication_server',
    attestKeyId: Buffer.alloc(32, 5).toString('base64'),
    documentChallengeId: Buffer.alloc(16, 6).toString('base64url'),
    dg14Hash: 'e'.repeat(64),
  });
  assert.equal(outcome, 'verified');
  assert.match(observed, /^SELECT activate_self_hosted_verified_id_v7_ca_rotating\(/);
  assert.match(observed, /chip_authentication_server/);
  assert.match(observed, /e{64}/);
});

test('review adapter rejects injected or automatic CA-only assurance', async () => {
  const store = createProductionVerificationStore(async () => [['pending']]);
  const base = {
    documentToken: 'a'.repeat(64),
    legacyDocumentToken: null,
    contributorId: UUID_A,
    faceModel: 'coreml',
    faceModelVersion: 'facenet-vggface2-coreml-04a4db780288799e',
    faceScore: 0.75,
    faceThreshold: 0.5,
    faceSampleCount: 3,
    faceContinuityScore: 0.7,
    livenessFrameCount: 20,
    livenessDurationMs: 3000,
    protocolVersion: 7,
    documentAssurance: 'chip_authentication_attested',
  };
  assert.equal(await store.submitReviewV7(base), 'pending');
  await assert.rejects(() => store.submitReviewV7({
    ...base,
    contributorId: `${UUID_A}'; DROP TABLE contributors;--`,
  }));
  await assert.rejects(() => store.activateSelfHostedV7({
    ...base,
    requestId: UUID_B,
    policyVersion: 'ostrovua-self-hosted-2026-07-v1',
    modelSetHash: 'b'.repeat(64),
    receiptDigest: 'c'.repeat(64),
    receiptSignature: 'd'.repeat(64),
    serviceTimestamp: 1_784_929_000,
    documentAssurance: 'chip_authentication_attested',
  }));
});
