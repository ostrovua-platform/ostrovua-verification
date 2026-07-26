'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseSelfHostedEnvelope,
  validateCanonicalBase64,
} = require('../self_hosted_contract');

function validEnvelope() {
  return {
    contract: 'self-hosted-envelope-v3',
    keyId: 'a'.repeat(64),
    ephemeralPublicKey: Buffer.alloc(32, 1).toString('base64'),
    nonce: Buffer.alloc(12, 2).toString('base64'),
    ciphertext: Buffer.alloc(128, 3).toString('base64'),
  };
}

test('accepts only the exact opaque envelope and preserves ciphertext', () => {
  const source = validEnvelope();
  const parsed = parseSelfHostedEnvelope(source);
  assert.deepEqual(parsed, source);
  assert.equal(Object.hasOwn(parsed, 'rawDataGroups'), false);
  assert.equal(Object.hasOwn(parsed, 'biometricEvidence'), false);
});

test('rejects every legacy production envelope contract', () => {
  const source = validEnvelope();
  for (const contract of ['self-hosted-envelope-v1', 'self-hosted-envelope-v2']) {
    source.contract = contract;
    assert.throws(() => parseSelfHostedEnvelope(source), /shape_invalid/);
  }
});

test('rejects non-canonical base64, wrong key sizes and unknown fields', () => {
  assert.throws(
    () => validateCanonicalBase64('YWJj\n', null, 16, 'x'),
    /base64_invalid/,
  );
  const shortKey = validEnvelope();
  shortKey.ephemeralPublicKey = Buffer.alloc(31).toString('base64');
  assert.throws(() => parseSelfHostedEnvelope(shortKey), /base64_invalid/);

  const unknown = validEnvelope();
  unknown.debug = true;
  assert.throws(() => parseSelfHostedEnvelope(unknown), /shape_invalid/);
});

test('rejects malformed key ids and empty ciphertext', () => {
  const key = validEnvelope();
  key.keyId = 'A'.repeat(64);
  assert.throws(() => parseSelfHostedEnvelope(key), /shape_invalid/);

  const empty = validEnvelope();
  empty.ciphertext = '';
  assert.throws(() => parseSelfHostedEnvelope(empty), /base64_invalid/);
});
