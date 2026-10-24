'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  hashRawDataGroups,
  validateRawDataGroups,
} = require('../passiveauth');

function groups() {
  return {
    dg1: Buffer.from('dg1-signed-content'),
    dg2: Buffer.from('dg2-signed-content'),
    dg14: Buffer.from('dg14-security-infos'),
    dg15: Buffer.from('dg15-aa-public-key'),
  };
}

test('DG14 and DG15 are validated and hashed with the signed document groups', () => {
  const input = groups();
  assert.deepEqual(Object.keys(validateRawDataGroups(input)).sort(),
    ['dg1', 'dg14', 'dg15', 'dg2']);

  const hashes = hashRawDataGroups(input, 'sha256');
  for (const [name, value] of Object.entries(input)) {
    assert.equal(hashes[name], crypto.createHash('sha256').update(value).digest('hex'));
  }
});

test('document-group validator rejects unknown, empty, or oversized active-auth evidence', () => {
  const unknown = { ...groups(), dg16: Buffer.from('unexpected') };
  assert.throws(() => validateRawDataGroups(unknown), /raw_dg_shape_invalid/);

  const empty = groups();
  empty.dg15 = Buffer.alloc(0);
  assert.throws(() => validateRawDataGroups(empty), /raw_dg_size_invalid/);

  const oversized = groups();
  oversized.dg14 = Buffer.alloc(128 * 1024 + 1);
  assert.throws(() => validateRawDataGroups(oversized), /raw_dg_size_invalid/);
});

test('production requires active-auth groups while calibration verifies the same signed SOD with DG1/DG2', async t => {
  const fs = require('node:fs');
  const path = require('node:path');
  const os = require('node:os');
  const vm = require('node:vm');
  const { createRequire } = require('node:module');
  const { execFileSync } = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-calibration-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const write = (name, value) => fs.writeFileSync(path.join(dir, name), value);
  const ssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe', timeout: 15000 });
  ssl('req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-days', '2',
    '-subj', '/C=UA/O=Synthetic Test/CN=CSCA', '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  ssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-nodes', '-keyout', 'signer.key', '-out', 'signer.csr', '-subj', '/C=UA/O=Synthetic Test/CN=DSC');
  write('index', ''); write('serial', '1000\n'); write('crlnumber', '1000\n');
  fs.mkdirSync(path.join(dir, 'issued'));
  write('ca.cnf', '[ca]\ndefault_ca=local\n[local]\ndatabase=index\nserial=serial\n' +
    'crlnumber=crlnumber\nnew_certs_dir=issued\ncertificate=root.pem\nprivate_key=root.key\n' +
    'default_md=sha256\ndefault_days=2\ndefault_crl_days=2\npolicy=policy\nx509_extensions=leaf\n' +
    '[policy]\ncountryName=match\norganizationName=supplied\ncommonName=supplied\n' +
    '[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
  ssl('ca', '-batch', '-notext', '-config', 'ca.cnf', '-in', 'signer.csr', '-out', 'signer.pem');
  ssl('ca', '-gencrl', '-config', 'ca.cnf', '-out', 'root.crl');
  function der(tag, ...parts) {
    const body = Buffer.concat(parts);
    return Buffer.concat([Buffer.from([tag, ...(body.length < 128 ? [body.length] : [0x82, body.length >> 8, body.length & 255])]), body]);
  }
  const hashes = Object.fromEntries(Object.entries(groups()).map(([name, value]) =>
    [name, { sha256: crypto.createHash('sha256').update(value).digest('hex') }]));
  const algorithm = der(0x30, der(0x06, Buffer.from('608648016503040201', 'hex')), der(0x05));
  write('lds.der', der(0x30, der(0x02, Buffer.from([0])), algorithm, der(0x30,
    ...[[1, 'dg1'], [2, 'dg2'], [14, 'dg14'], [15, 'dg15']].map(([number, name]) =>
      der(0x30, der(0x02, Buffer.from([number])), der(0x04, Buffer.from(hashes[name].sha256, 'hex')))))));
  ssl('cms', '-sign', '-binary', '-nodetach', '-md', 'sha256', '-in', 'lds.der',
    '-signer', 'signer.pem', '-inkey', 'signer.key', '-outform', 'DER', '-out', 'sod.der');
  const sodBase64 = fs.readFileSync(path.join(dir, 'sod.der')).toString('base64');
  const source = path.resolve(__dirname, '../passiveauth.js');
  const context = { module: { exports: {} }, require: createRequire(source), Buffer,
    __dirname: path.dirname(source), setTimeout, clearTimeout, console,
    process: { env: { CSCA_MASTERLIST: path.join(dir, 'root.pem'), CSCA_CRL: path.join(dir, 'root.crl'),
      CSCA_DSC_LOOKUP: path.join(dir, 'signer.pem'), PA_REVOCATION_MODE: 'best_effort', APP_ENV: 'production' } } };
  vm.runInNewContext(fs.readFileSync(source, 'utf8'), context);
  const { verifySOD } = context.module.exports;
  const minimal = { dg1: hashes.dg1, dg2: hashes.dg2 };
  for (const evaluationOnly of [undefined, false, 'true']) {
    const result = await verifySOD({ sodBase64, dgHashes: minimal, evaluationOnly });
    assert.equal(result.status, 'failed');
    assert.match(result.reason, /dg14.*missing/);
  }
  const withoutDG15 = { ...minimal, dg14: hashes.dg14 };
  const missingDG15 = await verifySOD({ sodBase64, dgHashes: withoutDG15 });
  assert.equal(missingDG15.status, 'failed');
  assert.match(missingDG15.reason, /dg15.*missing/);
  assert.equal((await verifySOD({ sodBase64, dgHashes: hashes })).status, 'passed');
  assert.equal((await verifySOD({ sodBase64, dgHashes: minimal, evaluationOnly: true })).status, 'passed');
  for (const group of ['dg1', 'dg2']) {
    const changed = { ...minimal, [group]: { sha256: '00'.repeat(32) } };
    assert.equal((await verifySOD({ sodBase64, dgHashes: changed, evaluationOnly: true })).status, 'failed');
  }
  const damaged = Buffer.from(sodBase64, 'base64'); damaged[damaged.length - 1] ^= 1;
  assert.equal((await verifySOD({ sodBase64: damaged.toString('base64'), dgHashes: minimal, evaluationOnly: true })).status, 'failed');
});
