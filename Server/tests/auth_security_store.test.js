'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createAuthSecurityStore } = require('../auth_security_store');

const PEPPER_A = 'rate-limit-pepper-32-bytes-minimum-value';
const PEPPER_B = 'session-metadata-pepper-32-bytes-minimum';
const CONTRIBUTOR_ID = '018f3f0a-4f90-7b65-8d31-167574b21ca1';
const SESSION_ID = '018f3f0a-5fa0-7b65-8d31-167574b21ca2';
const RECEIPT_ID = '018f3f0a-6fa0-7b65-8d31-167574b21ca3';
const ATTEST_KEY_ID = Buffer.alloc(32, 7).toString('base64');
const DOCUMENT_CHALLENGE_ID = Buffer.alloc(16, 9).toString('base64url');
const PASSWORD_HASH = `ovua$bcrypt-sha512$v1$$2b$12$${'a'.repeat(53)}`;

function storeWith(result) {
  const calls = [];
  const store = createAuthSecurityStore(async (sql) => {
    calls.push(sql);
    return typeof result === 'function' ? result(sql) : result;
  }, {
    rateLimitPepper: PEPPER_A,
    metadataPepper: PEPPER_B,
  });
  return { store, calls };
}

test('rate-limit identities are HMACed and raw identity never reaches SQL', async () => {
  const { store, calls } = storeWith([[true, '0']]);
  const identity = 'email:person@example.test';
  const outcome = await store.consumeRateLimit({
    bucket: 'login:email',
    identity,
    limit: 5,
    windowSeconds: 900,
    blockSeconds: 3600,
  });

  assert.deepEqual(outcome, { allowed: true, retryAfterSeconds: 0 });
  assert.equal(calls.length, 1);
  assert.doesNotMatch(calls[0], /person@example\.test/);
  assert.match(calls[0], /[0-9a-f]{64}/);
  await assert.rejects(
    store.consumeRateLimit({
      bucket: "login'); DROP TABLE contributors;--",
      identity,
      limit: 5,
      windowSeconds: 900,
      blockSeconds: 3600,
    }),
    /bucket_invalid/
  );
});

test('session operations validate UUIDs and never store raw metadata', async () => {
  const { store, calls } = storeWith([[true]]);
  await store.createSession({
    sessionId: SESSION_ID,
    contributorId: CONTRIBUTOR_ID,
    expiresAt: new Date(Date.now() + 60_000),
    ip: '203.0.113.44',
    userAgent: 'Private browser string',
  });

  assert.doesNotMatch(calls[0], /203\.0\.113\.44|Private browser string/);
  assert.match(calls[0], /[0-9a-f]{64}/);
  await assert.rejects(
    store.isSessionActive({ sessionId: 'not-a-uuid', contributorId: CONTRIBUTOR_ID }),
    /auth_session_id_invalid/
  );
});

test('password mutation requires versioned hash and returns explicit reset outcome', async () => {
  const { store } = storeWith((sql) => (
    sql.includes('secure_password_reset') ? [['changed']] : [[true]]
  ));

  await store.changePassword({
    contributorId: CONTRIBUTOR_ID,
    currentPasswordHash: `$2b$12$${'b'.repeat(53)}`,
    passwordHash: PASSWORD_HASH,
  });
  assert.equal(await store.resetPassword({
    contributorId: CONTRIBUTOR_ID,
    candidateHash: 'a'.repeat(64),
    passwordHash: PASSWORD_HASH,
  }), 'changed');
  await assert.rejects(
    store.changePassword({
      contributorId: CONTRIBUTOR_ID,
      currentPasswordHash: `$2b$12$${'b'.repeat(53)}`,
      passwordHash: '$2b$12$legacy',
    }),
    /password_hash_format_invalid/
  );
});

test('account deletion result and durable file queue are strictly validated', async () => {
  const filename = `${'a'.repeat(32)}.jpg`;
  const { store } = storeWith((sql) => {
    if (sql.includes('delete_account_complete')) {
      return [[JSON.stringify({ status: 'deleted', files: [filename], counts: {} })]];
    }
    if (sql.includes('account_deletion_pending_files')) {
      return [[RECEIPT_ID, filename]];
    }
    return [[true]];
  });

  const deletion = await store.deleteAccount({
    contributorId: CONTRIBUTOR_ID,
    receiptId: RECEIPT_ID,
  });
  assert.deepEqual(deletion.files, [filename]);
  assert.deepEqual(await store.pendingDeletionFiles(), [{
    receiptId: RECEIPT_ID,
    filename,
  }]);
});

test('document CA receipts are typed, one-time database records without raw DG14', async () => {
  const { store, calls } = storeWith([[true]]);
  const recorded = await store.recordDocumentCAReceipt({
    sessionId: SESSION_ID,
    contributorId: CONTRIBUTOR_ID,
    attestKeyId: ATTEST_KEY_ID,
    documentChallengeId: DOCUMENT_CHALLENGE_ID,
    dg14Hash: 'd'.repeat(64),
    protocolOID: '0.4.0.127.0.7.2.2.3.2.2',
    keyId: 1,
    expiresAt: new Date(Date.now() + 60_000),
  });
  assert.equal(recorded, true);
  assert.equal(await store.hasDocumentCAReceipt({
    contributorId: CONTRIBUTOR_ID,
    attestKeyId: ATTEST_KEY_ID,
    documentChallengeId: DOCUMENT_CHALLENGE_ID,
    dg14Hash: 'd'.repeat(64),
  }), true);
  assert.match(calls[0], /document_ca_record_receipt/);
  assert.match(calls[1], /document_ca_receipt_available/);
  assert.doesNotMatch(calls.join('\n'), /BEGIN CERTIFICATE|DG14|passport/i);

  await assert.rejects(store.recordDocumentCAReceipt({
    sessionId: SESSION_ID,
    contributorId: CONTRIBUTOR_ID,
    attestKeyId: ATTEST_KEY_ID,
    documentChallengeId: DOCUMENT_CHALLENGE_ID,
    dg14Hash: 'd'.repeat(64),
    protocolOID: '0.4.0.127.0.7.2.2.3.2.1',
    keyId: 1,
    expiresAt: new Date(Date.now() + 60_000),
  }), /document_ca_receipt_invalid/);
});
