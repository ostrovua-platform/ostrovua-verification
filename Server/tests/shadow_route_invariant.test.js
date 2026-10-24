'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('node:vm');
const crypto = require('node:crypto');

test('evaluation-only route exits before every document-token and database mutation', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'server.js'), 'utf8');
  const approvalStart = source.indexOf("app.post('/auth/verify/approve'");
  const calibrationMarker = source.indexOf(
    '// Shadow/PAD calibration stops here.',
    approvalStart
  );
  const branchStart = source.indexOf('if (evaluationOnly) {', calibrationMarker);
  const documentTokenStart = source.indexOf(
    'if (!DOC_TOKEN_PEPPER)',
    branchStart
  );
  assert.ok(approvalStart > 0);
  assert.ok(calibrationMarker > approvalStart);
  assert.ok(branchStart > 0);
  assert.ok(documentTokenStart > branchStart);

  const branch = source.slice(branchStart, documentTokenStart);
  assert.match(branch, /status:\s*'calibration'/);
  assert.match(branch, /verified:\s*false/);
  assert.match(branch, /evaluationOnly:\s*true/);
  assert.match(branch, /calibrationSignals:\s*serverBiometrics\.calibrationSignals/);
  assert.match(branch, /return res\.json/);
  assert.doesNotMatch(branch, /hasuraSQL|activate_self_hosted_verified_id|docToken/);
});

test('both passive-auth calls receive the server-selected calibration mode', async () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  const start = source.indexOf('  let pa;', source.indexOf("app.post('/auth/verify/approve'"));
  const end = source.indexOf("  if (pa.status !== 'passed')", start);
  assert.ok(start > 0 && end > start);
  for (const evaluationOnly of [false, true]) {
    const calls = [];
    const dgHashes = { dg1: { sha256: '11'.repeat(32) }, dg2: { sha256: '22'.repeat(32) } };
    const context = { Buffer, crypto, console, evaluationOnly, protocolVersion: 7,
      verificationPolicy: { PROTOCOL_VERSION: 7, deriveSequence: () => ['blink'] },
      body: { biometricEnvelope: { contract: 'synthetic' } },
      req: { rawBody: Buffer.from('synthetic') },
      res: { status() { throw new Error('valid synthetic evidence must not reject'); } },
      sod: 'synthetic-sod', dgHashes, activeAuthentication: 'passed',
      activeChallengeBytes: Buffer.alloc(32, 3), documentChallengeBytes: Buffer.alloc(32, 4),
      parseSelfHostedEnvelope: value => value,
      passiveauth: { verifySOD: async input => { calls.push(input); return { status: 'passed' }; } },
      biometricClient: { verifySelfHostedBiometrics: async () => ({
        evaluationOnly, dgHashes, documentAuthentication: { activeAuthentication: 'passed' },
      }) },
    };
    await vm.runInNewContext(`(async () => {${source.slice(start, end)}})()`, context);
    assert.equal(calls.length, 2);
    for (const call of calls) {
      assert.equal(call.evaluationOnly, evaluationOnly);
      assert.equal(call.sodBase64, 'synthetic-sod');
      assert.equal(call.dgHashes, dgHashes);
    }
  }
});

test('calibration challenge lane is allowlisted and never weakens production limits', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'server.js'), 'utf8');
  const routeStart = source.indexOf("app.post('/auth/verify/challenge'");
  const routeEnd = source.indexOf('async function verifyAppAttestAssertion', routeStart);
  const route = source.slice(routeStart, routeEnd);

  assert.match(route, /verificationMode/);
  assert.match(route, /isBiometricShadowAllowed/);
  assert.match(route, /CALIBRATION_MODE_FORBIDDEN/);
  assert.match(route, /SELF_HOSTED_VERIFICATION_DISABLED/);
  assert.ok(
    route.indexOf('SELF_HOSTED_VERIFICATION_DISABLED') < route.indexOf('rlTouch'),
    'closed production rollout must stop before consuming a liveness attempt'
  );
  assert.match(route, /purpose === 'liveness' && !calibrationChallenge/);
  assert.match(route, /`\$\{purpose\}_calibration`/);
  assert.match(route, /document_auth/);
  assert.match(route, /rlTouch/);

  const approval = source.slice(routeEnd);
  assert.match(approval, /expectedChallengePurpose/);
  assert.match(approval, /evaluationOnly[\s\S]*liveness_calibration[\s\S]*liveness/);
  assert.match(approval, /evaluationOnly[\s\S]*document_auth_calibration[\s\S]*document_auth/);
  const calls = [...approval.matchAll(/passiveauth\.verifySOD\(\{([\s\S]*?)\}\)/g)];
  assert.equal(calls.length, 2, 'both precheck and authoritative PA must remain bound to server mode');
  for (const call of calls) {
    assert.match(call[1], /evaluationOnly/);
    assert.doesNotMatch(call[1], /requiredDataGroups/);
  }
});
