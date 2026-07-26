'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

function source(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

test('production route has no legacy challenge or evidence compatibility', () => {
  const route = source('server.js');
  const policy = source('verification_policy.js');
  const contract = source('self_hosted_contract.js');
  const legacyPatcher = source('tools/patch_production_v5.py');

  assert.match(policy, /const PROTOCOL_VERSION = 7;/);
  assert.doesNotMatch(policy, /LEGACY_PROTOCOL|protocolVersion\s*===\s*6/);
  assert.doesNotMatch(route, /purpose\s*\|\|\s*['"]legacy['"]/);
  assert.doesNotMatch(route, /consumeChallenge\([^)]*legacy/s);
  assert.match(contract, /self-hosted-envelope-v3/);
  assert.doesNotMatch(contract, /self-hosted-envelope-v[12]/);
  assert.match(legacyPatcher, /DISABLED: protocol v5\/v6 production patching is forbidden/);
});

test('critical verification boundaries use the persistent limiter fail closed', () => {
  const route = source('server.js');
  const migration = source('migrations/20260724_verification_rate_limit_fail_closed.sql');

  assert.match(route, /const rlCheck = \(key\) => rlQuery\('rl_check', key\)/);
  assert.match(route, /verification_rate_limit_identity_incomplete/);
  assert.match(route, /purpose === 'document_auth'[\s\S]*await rlCheck\(key\)/);
  assert.match(
    route,
    /serverOwnedCAEnabled:[\s\S]*serverOwnedCALane\(contributorId, verificationMode\)/
  );
  assert.match(route, /if \(!evaluationOnly\)[\s\S]*await rlCheck\(key\)/);
  assert.ok((route.match(/VERIFICATION_RATE_LIMIT_UNAVAILABLE/g) || []).length >= 3);
  assert.match(migration, /CREATE OR REPLACE FUNCTION public\.rl_check/);
  assert.match(migration, /FOR UPDATE/);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.rl_check\(text\) FROM PUBLIC/);
});

test('protocol v7 database entry points persist document assurance', () => {
  const route = source('server.js');
  const migration = source('migrations/20260724_document_assurance_v7.sql');
  const caMigration = source('migrations/20260725_server_owned_ca.sql');

  assert.match(route, /activateSelfHostedV7/);
  assert.match(route, /activateSelfHostedCAV7/);
  assert.match(route, /submitReviewV7/);
  assert.match(migration, /p_evidence_protocol IS DISTINCT FROM 7/);
  assert.match(migration, /'passive_only', 'chip_authentication_attested'/);
  assert.match(migration, /chip_authentication_attested/);
  assert.match(migration, /p_document_assurance IS DISTINCT FROM\s+'active_authentication'/);
  assert.match(migration, /evidence_protocol = 7/);
  assert.match(migration, /document_assurance = p_document_assurance/);
  assert.match(caMigration, /'chip_authentication_server'/);
  assert.match(
    caMigration,
    /activate_self_hosted_verified_id_v7_ca_rotating/
  );
});

test('automatic activation requires server-verified AA or one-time server CA', () => {
  const route = source('server.js');
  const assurance = route.slice(
    route.indexOf('const documentAssurance'),
    route.indexOf('// ── «Один документ = один акаунт»')
  );

  assert.match(assurance, /active_authentication/);
  assert.match(assurance, /chip_authentication_server/);
  assert.doesNotMatch(assurance, /passive_only\s*===/);
  assert.match(route, /hasDocumentCAReceipt/);
  assert.match(route, /activateSelfHostedCAV7/);
  assert.match(route, /documentAssurance === 'chip_authentication_server'/);
  assert.match(route, /biometric_envelope_document_auth_mismatch/);
  assert.match(route, /documentAuthenticationChallengeId/);
});

test('client face verdict cannot bypass authoritative server face match', () => {
  const route = source('server.js');
  const serverDecisionGate = route.indexOf(
    "serverBiometrics.decision !== 'passed'"
  );
  const assuranceDecision = route.indexOf('const documentAssurance');
  const activation = route.indexOf('activateSelfHostedV7');

  assert.ok(serverDecisionGate > 0);
  assert.ok(
    serverDecisionGate < assuranceDecision,
    'server biometric decision must gate document assurance'
  );
  assert.ok(
    serverDecisionGate < activation,
    'server biometric decision must gate automatic activation'
  );
  assert.match(
    route,
    /serverBiometrics\s*=\s*await biometricClient\.verifySelfHostedBiometrics/
  );
});

test('the production biometric image contains fail-closed replay and document-auth modules', () => {
  const app = source('biometric_service/app.py');
  const cache = source('biometric_service/replay_cache.py');
  const dockerfile = source('biometric_service/Dockerfile');

  assert.match(app, /NonceReplayCache/);
  assert.match(app, /REPLAY_CACHE\.consume\(nonce\)/);
  assert.match(cache, /os\.O_CREAT\s*\|\s*os\.O_EXCL/);
  assert.match(cache, /Never fail open/);
  assert.match(dockerfile, /document_auth\.py/);
  assert.match(dockerfile, /replay_cache\.py/);
});

test('the production auth image runs as a fixed non-root user', () => {
  const dockerfile = source('Dockerfile');
  const composeBuilder = source('tools/build_dark_compose.py');
  const composeGate = source('tools/check_selfhosted_compose.py');
  const userDeclaration = dockerfile.lastIndexOf('USER 12000:12000');
  const commandDeclaration = dockerfile.lastIndexOf('CMD ["node", "server.js"]');

  assert.match(
    dockerfile,
    /addgroup -S -g 12000 ostrovua-auth[\s\S]*adduser -S -D -H -u 12000 -G ostrovua-auth ostrovua-auth/
  );
  assert.match(dockerfile, /chown 12000:12000 \/app\/uploads/);
  assert.ok(userDeclaration > 0, 'auth image must declare its runtime user');
  assert.ok(
    userDeclaration < commandDeclaration,
    'the non-root user must apply to the runtime command'
  );
  assert.doesNotMatch(
    dockerfile.slice(userDeclaration),
    /USER\s+(?:0(?::0)?|root(?::root)?)\b/
  );
  assert.match(composeBuilder, /auth\["user"\]\s*=\s*"12000:12000"/);
  assert.match(
    composeGate,
    /auth\.get\("user", ""\)[\s\S]*!=\s*"12000:12000"/
  );
});

test('DSC lookup material cannot become active-snapshot trust implicitly', () => {
  const passiveAuthentication = source('passiveauth.js');

  assert.match(passiveAuthentication, /const ACTIVE_DSC_BUNDLE/);
  assert.match(passiveAuthentication, /const DSC_LOOKUP_BUNDLE/);
  assert.match(
    passiveAuthentication,
    /verifyArgs\.push\('-certfile', DSC_LOOKUP_BUNDLE\)/
  );
  assert.match(
    passiveAuthentication,
    /loadFreshActiveDSCBundle\(bundlePath, minimumCertificates\)/
  );
  assert.doesNotMatch(
    passiveAuthentication,
    /loadFreshActiveDSCBundle\([^)]*DSC_LOOKUP_BUNDLE/
  );
});
