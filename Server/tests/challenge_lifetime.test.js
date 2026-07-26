'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const appattest = require('../appattest');

function assertLifetime(challenge, expectedSeconds, issuedAfter, issuedBefore) {
  assert.equal(challenge.expiresInSeconds, expectedSeconds);
  const expiresAt = Date.parse(challenge.expiresAt);
  assert.ok(Number.isFinite(expiresAt));
  assert.ok(
    expiresAt >= issuedAfter + (expectedSeconds * 1000),
    'challenge must not be shorter than its declared lifetime'
  );
  assert.ok(
    expiresAt <= issuedBefore + (expectedSeconds * 1000),
    'challenge must not exceed its declared lifetime'
  );
}

test('physical-operation challenges use short owner-bound one-shot windows', () => {
  const contributorId = 'b6fba49a-f5df-4ae1-b7af-b7f6e15ba1ee';
  const issuedAfter = Date.now();
  const document = appattest.issueChallenge(
    contributorId,
    'document_auth'
  );
  const liveness = appattest.issueChallenge(
    contributorId,
    'liveness'
  );
  const issuedBefore = Date.now();

  assertLifetime(document, 90, issuedAfter, issuedBefore);
  assertLifetime(liveness, 90, issuedAfter, issuedBefore);

  // A foreign caller cannot inspect or burn the legitimate owner's nonce.
  assert.equal(
    appattest.consumeChallenge(
      document.id,
      '1f189f35-201d-4e60-b21c-a5060ce1d156',
      'document_auth'
    ),
    null
  );
  const consumed = appattest.consumeChallenge(
    document.id,
    contributorId,
    'document_auth'
  );
  assert.equal(consumed.length, 32);
  consumed.fill(0);
  assert.equal(
    appattest.consumeChallenge(
      document.id,
      contributorId,
      'document_auth'
    ),
    null,
    'document challenge must be strictly one-shot'
  );

  const liveBytes = appattest.consumeChallenge(
    liveness.id,
    contributorId,
    'liveness'
  );
  liveBytes.fill(0);
});

test('App Attest registration keeps its separate five-minute window', () => {
  const issuedAfter = Date.now();
  const challenge = appattest.issueChallenge(
    'b6fba49a-f5df-4ae1-b7af-b7f6e15ba1ee',
    'attestation'
  );
  const issuedBefore = Date.now();
  assertLifetime(challenge, 300, issuedAfter, issuedBefore);
  const bytes = appattest.consumeChallenge(
    challenge.id,
    'b6fba49a-f5df-4ae1-b7af-b7f6e15ba1ee',
    'attestation'
  );
  bytes.fill(0);
});
