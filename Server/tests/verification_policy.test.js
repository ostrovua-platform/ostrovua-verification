'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  FACE_MODEL_VERSION,
  deriveSequence,
  isBiometricShadowAllowed,
  isSelfHostedVerificationEnabled,
  sequenceFingerprint,
  validateBiometricEvidence,
} = require('../verification_policy');

const seed = Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex');

function validBody() {
  return {
    protocolVersion: 7,
    liveness: 'active',
    activeLiveness: 'passed',
    faceMatch: 'passed',
    faceModel: 'coreml',
    faceModelVersion: FACE_MODEL_VERSION,
    faceMatchScore: 0.63,
    faceMatchThreshold: 0.50,
    faceSampleCount: 4,
    faceContinuityScore: 0.72,
    activeLivenessEvidence: {
      sequenceHash: sequenceFingerprint(seed),
      frameCount: 120,
      faceSampleCount: 4,
      durationMs: 4200,
      completedActions: 2,
      multipleFaceFrames: 0,
    },
  };
}

test('challenge sequence is deterministic and has no immediate repeats', () => {
  const first = deriveSequence(seed);
  assert.deepEqual(first, deriveSequence(seed));
  assert.equal(first.length, 2);
  assert.notEqual(first[0], first[1]);
  assert.match(sequenceFingerprint(seed), /^[0-9a-f]{64}$/);
});

test('self-hosted rollout switch is fail-closed and accepts only exact 1', () => {
  assert.equal(isSelfHostedVerificationEnabled(undefined), false);
  assert.equal(isSelfHostedVerificationEnabled('0'), false);
  assert.equal(isSelfHostedVerificationEnabled('true'), false);
  assert.equal(isSelfHostedVerificationEnabled('1 '), false);
  assert.equal(isSelfHostedVerificationEnabled('1'), true);
});

test('shadow mode requires exact switch and an exact UUID allowlist match', () => {
  const tester = 'f8c43df0-b9f3-4c85-a501-23c44305bfbd';
  const other = '2a4e2ee5-d3f1-48b5-8ad0-bf593c722d88';
  assert.equal(isBiometricShadowAllowed(tester, '0', tester), false);
  assert.equal(isBiometricShadowAllowed(tester, 'true', tester), false);
  assert.equal(isBiometricShadowAllowed(tester, '1', ''), false);
  assert.equal(isBiometricShadowAllowed(tester, '1', `invalid,${tester}`), false);
  assert.equal(isBiometricShadowAllowed(tester, '1', other), false);
  assert.equal(isBiometricShadowAllowed(tester, '1', ` ${other}, ${tester} `), true);
});

test('accepts complete protocol v7 only as an attested pre-check', () => {
  const result = validateBiometricEvidence(validBody(), seed);
  assert.equal(result.ok, true);
  assert.equal(result.normalized.faceSampleCount, 4);
  assert.equal(result.normalized.faceModelVersion, FACE_MODEL_VERSION);
});

test('rejects the legacy protocol v6 challenge contract', () => {
  const body = validBody();
  body.protocolVersion = 6;
  const result = validateBiometricEvidence(body, seed);
  assert.equal(result.ok, false);
});

test('rejects unknown protocol versions', () => {
  const body = validBody();
  body.protocolVersion = 8;
  assert.equal(validateBiometricEvidence(body, seed).ok, false);
});

test('rejects an uncalibrated or downgraded model', () => {
  const body = validBody();
  body.faceModelVersion = 'unknown-model';
  assert.equal(validateBiometricEvidence(body, seed).ok, false);
});

test('rejects score below the calibrated threshold', () => {
  const body = validBody();
  body.faceMatchScore = 0.49;
  assert.equal(validateBiometricEvidence(body, seed).ok, false);
});

test('rejects a single-frame assertion', () => {
  const body = validBody();
  body.faceSampleCount = 1;
  body.activeLivenessEvidence.faceSampleCount = 1;
  assert.equal(validateBiometricEvidence(body, seed).ok, false);
});

test('rejects evidence generated for another challenge', () => {
  const otherSeed = Buffer.alloc(32, 7);
  assert.equal(validateBiometricEvidence(validBody(), otherSeed).ok, false);
});

test('rejects any observed multi-face frame', () => {
  const body = validBody();
  body.activeLivenessEvidence.multipleFaceFrames = 1;
  assert.equal(validateBiometricEvidence(body, seed).ok, false);
});
