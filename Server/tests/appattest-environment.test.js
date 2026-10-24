'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const cbor = require('cbor');

const authRoot = path.join(__dirname, '..');
const attestPath = path.join(authRoot, 'appattest.js');
const attestSource = fs.readFileSync(attestPath, 'utf8');
const serverSource = fs.readFileSync(path.join(authRoot, 'server.js'), 'utf8');
const appId = 'AUDITTEST0.example.appattest.test';
const contributorId = '00000000-0000-4000-8000-000000000001';
const sha = value => crypto.createHash('sha256').update(value).digest();
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' });

function loadAttest(environment) {
  const env = { APPLE_TEAM_ID: 'AUDITTEST0', APP_BUNDLE_ID: 'example.appattest.test' };
  if (environment !== undefined) env.APPATTEST_ENV = environment;
  const context = { module: { exports: {} }, require: createRequire(attestPath),
    __dirname: authRoot, process: { env }, Buffer, Uint8Array, setInterval, console };
  vm.runInNewContext(attestSource, context, { filename: attestPath });
  return context.module.exports;
}

function signedAssertion(challengeBytes, bodyBytes, counter = 2) {
  const authenticatorData = Buffer.alloc(37);
  sha(Buffer.from(appId)).copy(authenticatorData);
  authenticatorData[32] = 0x40;
  authenticatorData.writeUInt32BE(counter, 33);
  const nonce = sha(Buffer.concat([authenticatorData, sha(Buffer.concat([challengeBytes, bodyBytes]))]));
  const signature = crypto.createSign('SHA256').update(nonce).sign(privateKey);
  return cbor.encode({ signature, authenticatorData }).toString('base64');
}

function evidence(storedEnvironment) {
  const challengeBytes = Buffer.alloc(32, 7);
  const bodyBytes = Buffer.from('{"synthetic":true}');
  return { assertionB64: signedAssertion(challengeBytes, bodyBytes),
    publicKeyPem, challengeBytes, bodyBytes, storedCounter: 1, storedEnvironment };
}

test('production keys remain valid in every configured server environment', () => {
  for (const environment of ['production', 'development', undefined, '', 'prodution']) {
    assert.equal(loadAttest(environment).verifyAssertion(evidence('production')), 2);
  }
});

test('development keys work only when the server explicitly enables development', () => {
  assert.equal(loadAttest('development').verifyAssertion(evidence('development')), 2);
  for (const environment of ['production', undefined, '', 'prodution', 'Development']) {
    assert.throws(() => loadAttest(environment).verifyAssertion(evidence('development')),
      error => error.appAttestFailureCode === 'APP_ATTEST_ENVIRONMENT_MISMATCH');
  }
});

test('missing or malformed stored key environments fail closed in both modes', () => {
  for (const serverEnvironment of ['production', 'development']) {
    const appattest = loadAttest(serverEnvironment);
    for (const storedEnvironment of [undefined, null, '', 'PRODUCTION', 'development ', {}, true]) {
      assert.throws(() => appattest.verifyAssertion(evidence(storedEnvironment)), error => {
        assert.equal(error.appAttestFailureCode, 'APP_ATTEST_KEY_ENVIRONMENT_INVALID');
        assert.equal(JSON.stringify(error.appAttestDiagnostics), '{}');
        return true;
      });
    }
  }
});

// Execute the actual assertion orchestration with a synthetic database and
// signed assertions. Loading server.js itself would start external services.
function routeHarness({ storedEnvironment = 'production', changedEnvironment, storedCounter = 1 } = {}) {
  const appattest = loadAttest('production');
  const keyId = Buffer.alloc(32, 4).toString('base64');
  const row = { key_id: keyId, public_key_pem: publicKeyPem,
    counter: storedCounter, environment: storedEnvironment };
  const queries = [];
  const logs = [];
  const context = { appattest, Buffer, console: { warn: (...args) => logs.push(args) },
    hasuraAdmin: async (query, values) => {
      queries.push({ query, values });
      assert.equal(values.k, keyId);
      if (query.trim().startsWith('query')) {
        assert.equal(values.c, contributorId);
        const fields = query.match(/\{ key_id ([^}]+)\}/)[1].trim().split(/\s+/);
        return { attest_keys: [{key_id:keyId, ...Object.fromEntries(fields.map(field => [field, row[field]]))}] };
      }
      assert.equal(values.c, contributorId, 'counter update remains bound to the authenticated owner');
      if (changedEnvironment !== undefined) row.environment = changedEnvironment;
      const sameEnvironment = /environment:\{_eq:\$e\}/.test(query) && row.environment === values.e;
      if (row.counter >= values.n || !sameEnvironment) return { update_attest_keys: { affected_rows: 0 } };
      row.counter = values.n;
      return { update_attest_keys: { affected_rows: 1 } };
    } };
  const start = serverSource.indexOf('const APP_ATTEST_DIAGNOSTIC_CODES =');
  const end = serverSource.indexOf('// Єдина точка атестації', start);
  assert.ok(start >= 0 && end > start);
  vm.runInNewContext(serverSource.slice(start, end), context);
  function request(bodyOverrides = {}) {
    const issued = appattest.issueChallenge(contributorId, 'attestation');
    const body = { challengeId: issued.id, ...bodyOverrides };
    const rawBody = Buffer.from(JSON.stringify(body));
    return { body, rawBody, verificationTrace: 'synthetic-trace', headers: {
      'x-attest-key': keyId,
      'x-app-attest': signedAssertion(Buffer.from(issued.challenge, 'base64'), rawBody),
    } };
  }
  return { context, queries, logs, row, request,
    verify: req => context.verifyAppAttestAssertion(req, contributorId) };
}

test('registered production key passes the route and advances its counter once', async () => {
  const harness = routeHarness();
  const req = harness.request();
  assert.equal(await harness.verify(req), true);
  assert.equal(harness.row.counter, 2);
  assert.equal(harness.queries.length, 2);
  assert.equal(await harness.verify(req), false);
  assert.equal(harness.queries.length, 2, 'consumed challenge cannot query or update the key again');
});

test('stored development key cannot be promoted by client fields or calibration mode', async () => {
  for (const verificationMode of ['production', 'calibration']) {
    const harness = routeHarness({ storedEnvironment: 'development' });
    const req = harness.request({ verificationMode, environment: 'production', storedEnvironment: 'production' });
    assert.equal(await harness.verify(req), false);
    assert.equal(harness.row.counter, 1);
    assert.equal(harness.queries.length, 1, 'rejected environment never updates the counter');
    assert.match(JSON.stringify(harness.logs), /APP_ATTEST_ENVIRONMENT_MISMATCH/);
    for (const secret of [publicKeyPem, req.headers['x-attest-key'], req.headers['x-app-attest'], contributorId]) {
      assert.ok(!JSON.stringify(harness.logs).includes(secret));
    }
  }
});

test('missing environment in a database record is rejected before counter mutation', async () => {
  const harness = routeHarness({ storedEnvironment: null });
  assert.equal(await harness.verify(harness.request()), false);
  assert.equal(harness.queries.length, 1);
  assert.match(JSON.stringify(harness.logs), /APP_ATTEST_KEY_ENVIRONMENT_INVALID/);
});

test('environment changes during assertion verification fail the atomic counter update', async () => {
  const harness = routeHarness({ changedEnvironment: 'development' });
  assert.equal(await harness.verify(harness.request()), false);
  assert.equal(harness.row.counter, 1);
  assert.match(JSON.stringify(harness.logs), /counter CAS conflict/);
});

test('production route still rejects an altered payload and a replayed counter', async () => {
  const altered = routeHarness();
  const req = altered.request();
  req.rawBody = Buffer.from('{"changed":true}');
  assert.equal(await altered.verify(req), false);
  assert.equal(altered.queries.length, 1);
  const replayed = routeHarness({ storedCounter: 2 });
  assert.equal(await replayed.verify(replayed.request()), false);
  assert.equal(replayed.queries.length, 1);
});

test('a rejected new approval never writes existing verification or session data', async () => {
  const harness = routeHarness({ storedEnvironment: 'development' });
  const account = Object.freeze({ id: contributorId, verified: true, identity_assurance: 'strong' });
  let handler;
  let workerCalls = 0;
  const context = { app: { post: (_path, _limit, callback) => { handler = callback; } },
    rateLimit() {}, requireContributor: async () => account.id,
    verifyDeviceAttestation: req => harness.verify(req),
    biometricClient: { verifySelfHostedBiometrics: async () => { workerCalls++; } },
    hasuraAdmin: () => { throw new Error('unexpected account/session mutation'); },
    hasuraSQL: () => { throw new Error('unexpected database mutation'); },
    console: { info() {} } };
  const start = serverSource.indexOf("app.post('/auth/verify/approve'");
  const end = serverSource.indexOf('\n});', start) + 4;
  assert.ok(start >= 0 && end > start);
  vm.runInNewContext(serverSource.slice(start, end), context);
  const res = { status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  await handler(harness.request(), res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, 'Device attestation required');
  assert.equal(workerCalls, 0);
  assert.equal(account.verified, true);
  assert.equal(account.identity_assurance, 'strong');
  assert.equal(harness.queries.length, 1);
  assert.equal(harness.row.counter, 1);
});
