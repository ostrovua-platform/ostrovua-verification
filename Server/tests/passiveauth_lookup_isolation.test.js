'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { execFileSync } = require('node:child_process');

const { requireFreshActiveDSC } = require('../passiveauth');

function makeCertificate(directory, name) {
  const key = path.join(directory, `${name}.key`);
  const cert = path.join(directory, `${name}.pem`);
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-subj', `/C=UA/O=OstrovUA test/CN=${name}`,
    '-days', '2', '-keyout', key, '-out', cert,
    '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature',
  ], { stdio: 'ignore' });
  return cert;
}

test('lookup-only DSC never satisfies active snapshot membership', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-lookup-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  const activeCertificate = makeCertificate(directory, 'active');
  const lookupOnlyCertificate = makeCertificate(directory, 'lookup-only');
  const activePem = fs.readFileSync(activeCertificate, 'utf8');
  const activeBundle = path.join(directory, 'active.pem');
  const sourceHash = crypto.createHash('sha256').update(activePem).digest('hex');
  fs.writeFileSync(activeBundle, [
    `# generated_at=${new Date().toISOString()}`,
    `# source_sha256=${sourceHash}`,
    // Production keeps the default floor of 90. This focused unit test passes
    // an explicit lower floor because it validates membership isolation.
  ].join('\n') + '\n');

  fs.appendFileSync(activeBundle, activePem);

  assert.equal(
    await requireFreshActiveDSC(activeCertificate, activeBundle, 1),
    null
  );
  assert.deepEqual(
    await requireFreshActiveDSC(lookupOnlyCertificate, activeBundle, 1),
    { status: 'failed', reason: 'dsc_not_active' }
  );
});
