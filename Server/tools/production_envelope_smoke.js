'use strict';

// Run inside the auth container. Uses synthetic non-biometric bytes to prove
// that the production public/private envelope key pair and authenticated
// internal route interoperate without exposing either secret.

const crypto = require('crypto');
const fs = require('fs');
const {
  loadEnvelopePublicKey,
  signRequest,
  verifyResponseSignature,
} = require('/app/biometric_client');

function uint32(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function blob(value) {
  return Buffer.concat([uint32(value.length), value]);
}

async function main() {
  const encodedSecret = process.env.BIOMETRIC_HMAC_SECRET || '';
  const secret = Buffer.from(encodedSecret, 'base64');
  if (secret.length < 32 || secret.toString('base64') !== encodedSecret) {
    throw new Error('invalid biometric service secret');
  }

  const challenge = crypto.randomBytes(32);
  const documentChallenge = crypto.randomBytes(32);
  const fakeJpeg = Buffer.from([0xff, 0xd8, 0xff, 0xd9]);
  const dg2 = Buffer.concat([Buffer.from([0x75, 0x04]), fakeJpeg]);
  const parts = [
    Buffer.from('OUVE3', 'ascii'),
    blob(Buffer.from('synthetic-dg1', 'ascii')),
    blob(dg2),
    blob(fakeJpeg),
    uint32(0), // no DG14
    uint32(0), // no DG15
    Buffer.from([0, 0]), // CA and AA not supported
    uint32(0), // no AA challenge
    uint32(0), // no AA signature
    Buffer.from([3]),
    blob(fakeJpeg), blob(fakeJpeg), blob(fakeJpeg),
    Buffer.from([12]),
  ];
  const depthGrid = Buffer.alloc(2 + 16 * 16 * 2);
  depthGrid[0] = 16;
  depthGrid[1] = 16;
  for (let index = 0; index < 16 * 16; index += 1) {
    depthGrid.writeUInt16BE(500, 2 + index * 2);
  }
  for (let index = 1; index <= 12; index += 1) {
    parts.push(uint32(index * 180), blob(fakeJpeg), blob(depthGrid));
  }
  const plaintext = Buffer.concat(parts);

  const keyInfo = loadEnvelopePublicKey();
  const rawPublic = fs.readFileSync(
    process.env.BIOMETRIC_ENVELOPE_PUBLIC_KEY_FILE ||
      '/app/certs/biometric_envelope_public.key');
  const spki = Buffer.concat([
    Buffer.from('302a300506032b656e032100', 'hex'),
    rawPublic,
  ]);
  const serverPublic = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  const ephemeral = crypto.generateKeyPairSync('x25519');
  const shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: serverPublic });
  const context = Buffer.from('ostrovua-biometric-envelope-v3', 'utf8');
  const aesKey = Buffer.from(crypto.hkdfSync('sha256', shared, challenge, context, 32));
  const aad = Buffer.concat([
    context, Buffer.from('\n'), Buffer.from(keyInfo.keyId, 'ascii'),
    Buffer.from('\n'), challenge,
  ]);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const ephemeralDer = ephemeral.publicKey.export({ format: 'der', type: 'spki' });
  const envelope = {
    contract: 'self-hosted-envelope-v3',
    keyId: keyInfo.keyId,
    ephemeralPublicKey: ephemeralDer.subarray(ephemeralDer.length - 32).toString('base64'),
    nonce: nonce.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };

  const requestId = crypto.randomUUID();
  const body = Buffer.from(JSON.stringify({
    contract: 'self-hosted-forward-v2',
    requestId,
    expectedActions: ['turnLeft', 'turnRight'],
    challenge: challenge.toString('base64'),
    documentChallenge: documentChallenge.toString('base64'),
    envelope,
    evaluationOnly: false,
  }), 'utf8');
  const timestamp = String(Math.floor(Date.now() / 1000));
  const requestNonce = crypto.randomBytes(16).toString('hex');
  const response = await fetch('http://biometric:8080/v1/verify', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-biometric-timestamp': timestamp,
      'x-biometric-nonce': requestNonce,
      'x-biometric-signature': signRequest(secret, timestamp, requestNonce, body),
    },
    body,
  });
  const responseBody = Buffer.from(await response.arrayBuffer());
  const result = JSON.parse(responseBody.toString('utf8'));
  const signatureValid = verifyResponseSignature(
    secret, requestId, responseBody, response.headers);

  plaintext.fill(0);
  aesKey.fill(0);
  aad.fill(0);
  encrypted.fill(0);
  depthGrid.fill(0);
  documentChallenge.fill(0);
  body.fill(0);
  responseBody.fill(0);
  secret.fill(0);
  rawPublic.fill(0);

  if (response.status !== 400 || result.error !== 'dg2_face_decode_failed' || !signatureValid) {
    throw new Error(`production envelope smoke failed: status=${response.status} ` +
      `error=${String(result.error)} signature=${signatureValid}`);
  }
  console.log(JSON.stringify({
    productionEnvelopeDecrypted: true,
    syntheticEvidenceRejected: true,
    responseSignatureValid: true,
  }));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
