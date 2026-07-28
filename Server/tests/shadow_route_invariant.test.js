'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

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
  assert.match(
    approval,
    /const paRequiredDataGroups = evaluationOnly[\s\S]*\['dg1', 'dg2'\][\s\S]*:\s*undefined/
  );
  assert.match(
    approval,
    /verifySOD\(\{[\s\S]*requiredDataGroups:\s*paRequiredDataGroups/
  );
});
