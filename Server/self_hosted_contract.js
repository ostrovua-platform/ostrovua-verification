'use strict';

// Ciphertext represents at most 8 MiB of biometric/document bytes plus a
// bounded binary framing overhead and the AES-GCM tag.
const MAX_CIPHERTEXT_BYTES = 8 * 1024 * 1024 + 2048;

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}

function validateCanonicalBase64(value, exactBytes, maxBytes, field) {
  const limit = exactBytes ?? maxBytes;
  const maxChars = Math.ceil(limit / 3) * 4;
  if (typeof value !== 'string' || value.length === 0 || value.length > maxChars ||
      value.length % 4 !== 0 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`${field}_base64_invalid`);
  }
  const decoded = Buffer.from(value, 'base64');
  const valid = (exactBytes === null || decoded.length === exactBytes) &&
    decoded.length <= maxBytes && decoded.toString('base64') === value;
  decoded.fill(0); // ciphertext/key material only; auth never sees plaintext
  if (!valid) throw new Error(`${field}_base64_invalid`);
}

/**
 * Validate only the opaque envelope. Decryption and binary evidence parsing
 * happen exclusively inside a one-request biometric worker.
 */
function parseSelfHostedEnvelope(value) {
  const fields = ['contract', 'keyId', 'ephemeralPublicKey', 'nonce', 'ciphertext'];
  if (!exactKeys(value, fields) ||
      value.contract !== 'self-hosted-envelope-v3' ||
      typeof value.keyId !== 'string' || !/^[0-9a-f]{64}$/.test(value.keyId)) {
    throw new Error('biometric_envelope_shape_invalid');
  }
  validateCanonicalBase64(value.ephemeralPublicKey, 32, 32, 'ephemeral_public_key');
  validateCanonicalBase64(value.nonce, 12, 12, 'envelope_nonce');
  validateCanonicalBase64(value.ciphertext, null, MAX_CIPHERTEXT_BYTES, 'envelope_ciphertext');
  return {
    contract: value.contract,
    keyId: value.keyId,
    ephemeralPublicKey: value.ephemeralPublicKey,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
  };
}

module.exports = {
  MAX_CIPHERTEXT_BYTES,
  validateCanonicalBase64,
  parseSelfHostedEnvelope,
};
