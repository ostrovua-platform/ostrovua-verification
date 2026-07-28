'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  hashRawDataGroups,
  normalizeRequiredDataGroups,
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

test('production requires active-auth groups while calibration may verify signed DG1/DG2 only', () => {
  assert.deepEqual(
    [...normalizeRequiredDataGroups()].sort(),
    ['dg1', 'dg14', 'dg15', 'dg2']
  );
  assert.deepEqual(
    [...normalizeRequiredDataGroups(['dg1', 'dg2'])].sort(),
    ['dg1', 'dg2']
  );
  assert.throws(
    () => normalizeRequiredDataGroups(['dg1']),
    /required_dg_policy_invalid/
  );
  assert.throws(
    () => normalizeRequiredDataGroups(['dg1', 'dg2', 'dg16']),
    /required_dg_policy_invalid/
  );
});
