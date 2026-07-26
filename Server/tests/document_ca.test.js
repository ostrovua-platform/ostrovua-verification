'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { createDocumentCA, parseDG14, _test } = require('../document_ca');

const ID_PK_ECDH = '0.4.0.127.0.7.2.2.1.2';
const ID_CA_ECDH_AES_128 = '0.4.0.127.0.7.2.2.3.2.2';

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const octets = [];
  let value = length;
  while (value > 0) {
    octets.unshift(value & 0xff);
    value >>>= 8;
  }
  return Buffer.from([0x80 | octets.length, ...octets]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function oid(value) {
  const arcs = value.split('.').map(Number);
  assert.ok(arcs.length >= 2);
  const values = [(arcs[0] * 40) + arcs[1], ...arcs.slice(2)];
  const encoded = [];
  for (const item of values) {
    const octets = [item & 0x7f];
    let remainder = Math.floor(item / 128);
    while (remainder > 0) {
      octets.unshift(0x80 | (remainder & 0x7f));
      remainder = Math.floor(remainder / 128);
    }
    encoded.push(...octets);
  }
  return tlv(0x06, Buffer.from(encoded));
}

function integer(value) {
  const octets = [];
  let remaining = value;
  do {
    octets.unshift(remaining & 0xff);
    remaining >>>= 8;
  } while (remaining > 0);
  if ((octets[0] & 0x80) !== 0) octets.unshift(0);
  return tlv(0x02, Buffer.from(octets));
}

function makeDG14(publicKey, keyId = 1) {
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const publicKeyInfo = tlv(0x30, Buffer.concat([
    oid(ID_PK_ECDH),
    spki,
    integer(keyId),
  ]));
  const protocolInfo = tlv(0x30, Buffer.concat([
    oid(ID_CA_ECDH_AES_128),
    integer(2),
    integer(keyId),
  ]));
  return tlv(0x6e, tlv(0x31, Buffer.concat([publicKeyInfo, protocolInfo])));
}

function publicKeyFromRawPoint(raw) {
  assert.equal(raw.length, 65);
  assert.equal(raw[0], 0x04);
  return crypto.createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: raw.subarray(1, 33).toString('base64url'),
      y: raw.subarray(33).toString('base64url'),
    },
    format: 'jwk',
  });
}

function aesEcb(key, block) {
  const cipher = crypto.createCipheriv(`aes-${key.length * 8}-ecb`, key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function protectResponse(ksEnc, ksMac, challenge) {
  const iv = aesEcb(ksEnc, _test.paddedSSC(2));
  const cipher = crypto.createCipheriv(`aes-${ksEnc.length * 8}-cbc`, ksEnc, iv);
  cipher.setAutoPadding(false);
  const ciphertext = Buffer.concat([
    cipher.update(_test.isoPad(challenge)),
    cipher.final(),
  ]);
  const do87 = tlv(0x87, Buffer.concat([Buffer.from([0x01]), ciphertext]));
  const do99 = tlv(0x99, Buffer.from([0x90, 0x00]));
  const macInput = _test.isoPad(Buffer.concat([_test.paddedSSC(2), do87, do99]));
  const mac = _test.aesCmac(ksMac, macInput).subarray(0, 8);
  return Buffer.concat([do87, do99, tlv(0x8e, mac)]);
}

test('AES-CMAC matches RFC 4493 vector', () => {
  const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c', 'hex');
  const message = Buffer.from('6bc1bee22e409f96e93d7e117393172a', 'hex');
  assert.equal(
    _test.aesCmac(key, message).toString('hex'),
    '070a16b46b4d4144f79bdd9dd04a287c'
  );
});

test('server-owned CA verifies an independently protected chip RAPDU', () => {
  const passport = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const dg14 = makeDG14(passport.publicKey);
  const candidates = parseDG14(dg14);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].keyLength, 128);

  const sealingKey = crypto.randomBytes(32);
  const documentCA = createDocumentCA(sealingKey, {
    now: () => Date.parse('2026-07-25T12:00:00.000Z'),
  });
  const binding = {
    contributorId: 'b6fba49a-f5df-4ae1-b7af-b7f6e15ba1ee',
    attestKeyId: crypto.randomBytes(32).toString('base64'),
    documentChallengeId: crypto.randomBytes(16).toString('base64url'),
  };
  const started = documentCA.start({
    rawDG14: dg14.toString('base64'),
    ...binding,
  });
  assert.equal(
    started.expiresAt,
    '2026-07-25T12:00:45.000Z',
    'live NFC relay token must expire after 45 seconds'
  );
  assert.equal(started.option.protocolOID, ID_CA_ECDH_AES_128);
  assert.equal(started.option.keyAgreementAlgorithm, 'ECDH');
  assert.equal(started.option.cipherAlgorithm, 'AES');

  const serverPublicKey = publicKeyFromRawPoint(
    Buffer.from(started.ephemeralPublicKey, 'base64')
  );
  const sharedSecret = crypto.diffieHellman({
    privateKey: passport.privateKey,
    publicKey: serverPublicKey,
  });
  const ksEnc = _test.deriveSessionKey(sharedSecret, 128, 1);
  const ksMac = _test.deriveSessionKey(sharedSecret, 128, 2);
  assert.equal(
    Buffer.from(started.protectedCommand, 'base64').toString('hex'),
    _test.protectGetChallenge(ksMac).toString('hex')
  );

  const response = protectResponse(ksEnc, ksMac, crypto.randomBytes(8));
  const completed = documentCA.complete({
    token: started.token,
    ...binding,
    responseData: response.toString('base64'),
    sw1: 0x90,
    sw2: 0x00,
  });
  assert.equal(completed.sessionId, started.sessionId);
  assert.equal(
    completed.expiresAt,
    '2026-07-25T12:03:00.000Z',
    'receipt TTL is independent from the shorter relay-token TTL'
  );
  assert.equal(completed.dg14Hash, crypto.createHash('sha256').update(dg14).digest('hex'));
  assert.equal(completed.protocolOID, ID_CA_ECDH_AES_128);

  sharedSecret.fill(0);
  ksEnc.fill(0);
  ksMac.fill(0);
  sealingKey.fill(0);
});

test('server-owned CA rejects transcript tampering and binding changes', () => {
  const passport = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const sealingKey = crypto.randomBytes(32);
  const documentCA = createDocumentCA(sealingKey);
  const binding = {
    contributorId: 'b6fba49a-f5df-4ae1-b7af-b7f6e15ba1ee',
    attestKeyId: crypto.randomBytes(32).toString('base64'),
    documentChallengeId: crypto.randomBytes(16).toString('base64url'),
  };
  const started = documentCA.start({ rawDG14: makeDG14(passport.publicKey), ...binding });
  const serverPublicKey = publicKeyFromRawPoint(
    Buffer.from(started.ephemeralPublicKey, 'base64')
  );
  const sharedSecret = crypto.diffieHellman({
    privateKey: passport.privateKey,
    publicKey: serverPublicKey,
  });
  const ksEnc = _test.deriveSessionKey(sharedSecret, 128, 1);
  const ksMac = _test.deriveSessionKey(sharedSecret, 128, 2);
  const response = protectResponse(ksEnc, ksMac, crypto.randomBytes(8));
  response[response.length - 1] ^= 0x01;

  assert.throws(() => documentCA.complete({
    token: started.token,
    ...binding,
    responseData: response.toString('base64'),
    sw1: 0x90,
    sw2: 0x00,
  }), { message: 'ca_response_mac_invalid' });

  assert.throws(() => documentCA.complete({
    token: started.token,
    ...binding,
    documentChallengeId: crypto.randomBytes(16).toString('base64url'),
    responseData: response.toString('base64'),
    sw1: 0x90,
    sw2: 0x00,
  }), { message: 'ca_token_binding_invalid' });

  sharedSecret.fill(0);
  ksEnc.fill(0);
  ksMac.fill(0);
  sealingKey.fill(0);
});
