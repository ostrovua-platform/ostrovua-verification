'use strict';

const crypto = require('crypto');

const ID_PK_ECDH = '0.4.0.127.0.7.2.2.1.2';
const CA_PROTOCOLS = Object.freeze({
  '0.4.0.127.0.7.2.2.3.2.2': Object.freeze({ code: 2, keyLength: 128 }),
  '0.4.0.127.0.7.2.2.3.2.3': Object.freeze({ code: 3, keyLength: 192 }),
  '0.4.0.127.0.7.2.2.3.2.4': Object.freeze({ code: 4, keyLength: 256 }),
});
const CA_PROTOCOLS_BY_CODE = Object.freeze(Object.fromEntries(
  Object.entries(CA_PROTOCOLS).map(([oid, value]) => [value.code, { oid, ...value }])
));
const CURVES = Object.freeze({
  prime256v1: Object.freeze({ jwk: 'P-256', coordinateBytes: 32 }),
  secp384r1: Object.freeze({ jwk: 'P-384', coordinateBytes: 48 }),
  secp521r1: Object.freeze({ jwk: 'P-521', coordinateBytes: 66 }),
});
const TOKEN_AAD = Buffer.from('ostrovua-document-ca-v1', 'ascii');
const TOKEN_VERSION = 1;
const TOKEN_TTL_MS = 2 * 60 * 1000;
const RECEIPT_TTL_MS = 5 * 60 * 1000;
const MAX_DG14_BYTES = 128 * 1024;
const MAX_PROTECTED_RESPONSE_BYTES = 1024;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function readLength(buffer, offset) {
  if (offset >= buffer.length) throw fail('ca_der_truncated');
  const first = buffer[offset];
  if (first < 0x80) return { length: first, bytes: 1 };
  if (first === 0x80) throw fail('ca_der_indefinite_length');
  const count = first & 0x7f;
  if (count === 0 || count > 4 || offset + 1 + count > buffer.length) {
    throw fail('ca_der_length_invalid');
  }
  if (buffer[offset + 1] === 0) throw fail('ca_der_length_non_minimal');
  let length = 0;
  for (let index = 0; index < count; index += 1) {
    length = (length * 256) + buffer[offset + 1 + index];
  }
  if (length < 0x80) throw fail('ca_der_length_non_minimal');
  return { length, bytes: 1 + count };
}

function readTLV(buffer, offset = 0) {
  if (!Buffer.isBuffer(buffer) || offset < 0 || offset >= buffer.length) {
    throw fail('ca_der_truncated');
  }
  let cursor = offset;
  const tagStart = cursor;
  cursor += 1;
  if ((buffer[tagStart] & 0x1f) === 0x1f) {
    let tagBytes = 0;
    while (cursor < buffer.length) {
      const byte = buffer[cursor];
      cursor += 1;
      tagBytes += 1;
      if (tagBytes > 4) throw fail('ca_der_tag_invalid');
      if ((byte & 0x80) === 0) break;
    }
    if ((buffer[cursor - 1] & 0x80) !== 0) throw fail('ca_der_tag_invalid');
  }
  const tag = buffer.subarray(tagStart, cursor);
  const decodedLength = readLength(buffer, cursor);
  cursor += decodedLength.bytes;
  const end = cursor + decodedLength.length;
  if (end > buffer.length) throw fail('ca_der_truncated');
  return {
    tag,
    content: buffer.subarray(cursor, end),
    raw: buffer.subarray(offset, end),
    end,
  };
}

function childrenOf(tlv) {
  const children = [];
  let offset = 0;
  while (offset < tlv.content.length) {
    const child = readTLV(tlv.content, offset);
    children.push(child);
    offset = child.end;
  }
  if (offset !== tlv.content.length) throw fail('ca_der_children_invalid');
  return children;
}

function oneByteTag(tlv, expected) {
  return tlv.tag.length === 1 && tlv.tag[0] === expected;
}

function decodeOID(content) {
  if (!Buffer.isBuffer(content) || content.length === 0 || content.length > 64) {
    throw fail('ca_der_oid_invalid');
  }
  const values = [];
  let value = 0;
  let open = false;
  for (const byte of content) {
    if (value > Math.floor(Number.MAX_SAFE_INTEGER / 128)) {
      throw fail('ca_der_oid_invalid');
    }
    value = (value * 128) + (byte & 0x7f);
    open = (byte & 0x80) !== 0;
    if (!open) {
      values.push(value);
      value = 0;
    }
  }
  if (open || values.length === 0) throw fail('ca_der_oid_invalid');
  const first = values.shift();
  const firstArc = first < 40 ? 0 : (first < 80 ? 1 : 2);
  const secondArc = first - (firstArc * 40);
  return [firstArc, secondArc, ...values].join('.');
}

function decodeInteger(tlv, { optional = false } = {}) {
  if (!tlv) {
    if (optional) return null;
    throw fail('ca_der_integer_missing');
  }
  if (!oneByteTag(tlv, 0x02) || tlv.content.length === 0 || tlv.content.length > 4 ||
      (tlv.content[0] & 0x80) !== 0 ||
      (tlv.content.length > 1 && tlv.content[0] === 0 && (tlv.content[1] & 0x80) === 0)) {
    throw fail('ca_der_integer_invalid');
  }
  let value = 0;
  for (const byte of tlv.content) value = (value * 256) + byte;
  return value;
}

function unwrapDG14(rawDG14) {
  if (!Buffer.isBuffer(rawDG14) || rawDG14.length < 4 ||
      rawDG14.length > MAX_DG14_BYTES) {
    throw fail('ca_dg14_invalid');
  }
  let root = readTLV(rawDG14);
  if (root.end !== rawDG14.length) throw fail('ca_dg14_trailing_data');
  if (oneByteTag(root, 0x6e)) {
    root = readTLV(root.content);
    if (root.end !== root.raw.length && root.end !== rawDG14.length) {
      throw fail('ca_dg14_wrapper_invalid');
    }
  }
  if (!oneByteTag(root, 0x31)) throw fail('ca_dg14_security_infos_missing');
  return root;
}

function parseDG14(rawDG14) {
  const securityInfos = childrenOf(unwrapDG14(rawDG14));
  const publicKeys = [];
  const protocols = [];

  for (const securityInfo of securityInfos) {
    if (!oneByteTag(securityInfo, 0x30)) throw fail('ca_security_info_invalid');
    const fields = childrenOf(securityInfo);
    if (fields.length < 2 || fields.length > 3 || !oneByteTag(fields[0], 0x06)) {
      throw fail('ca_security_info_invalid');
    }
    const oid = decodeOID(fields[0].content);
    if (oid === ID_PK_ECDH) {
      const keyId = decodeInteger(fields[2], { optional: true });
      let publicKey;
      try {
        publicKey = crypto.createPublicKey({
          key: fields[1].raw,
          format: 'der',
          type: 'spki',
        });
      } catch {
        throw fail('ca_public_key_invalid');
      }
      if (publicKey.asymmetricKeyType !== 'ec') throw fail('ca_public_key_not_ec');
      const namedCurve = publicKey.asymmetricKeyDetails?.namedCurve;
      if (!CURVES[namedCurve]) throw fail('ca_curve_unsupported');
      publicKeys.push({ keyId, publicKey, namedCurve });
    } else if (CA_PROTOCOLS[oid]) {
      const version = decodeInteger(fields[1]);
      if (![1, 2].includes(version)) throw fail('ca_protocol_version_unsupported');
      const keyId = decodeInteger(fields[2], { optional: true });
      protocols.push({ oid, keyId, ...CA_PROTOCOLS[oid] });
    }
  }

  const candidates = [];
  for (const publicKey of publicKeys) {
    for (const protocol of protocols) {
      if ((publicKey.keyId ?? 0) === (protocol.keyId ?? 0)) {
        candidates.push({ ...publicKey, ...protocol });
      }
    }
  }
  candidates.sort((left, right) => right.keyLength - left.keyLength);
  if (candidates.length === 0) throw fail('ca_unsupported');
  return candidates;
}

function strictBase64(value, maximumBytes, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(value) ||
      value.length > Math.ceil(maximumBytes / 3) * 4 + 4) {
    throw fail(`${label}_invalid`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.length > maximumBytes ||
      decoded.toString('base64') !== value) {
    decoded.fill(0);
    throw fail(`${label}_invalid`);
  }
  return decoded;
}

function strictBase64Url(value, expectedBytes, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) ||
      value.length > Math.ceil(expectedBytes * 4 / 3) + 1) {
    throw fail(`${label}_invalid`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== expectedBytes || decoded.toString('base64url') !== value) {
    decoded.fill(0);
    throw fail(`${label}_invalid`);
  }
  return decoded;
}

function uuidToBytes(value) {
  if (typeof value !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw fail('ca_contributor_id_invalid');
  }
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}

function bytesToUuid(value) {
  const hex = value.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isoPad(buffer, blockSize = 16) {
  const paddingBytes = blockSize - (buffer.length % blockSize);
  const output = Buffer.alloc(buffer.length + paddingBytes);
  buffer.copy(output);
  output[buffer.length] = 0x80;
  return output;
}

function isoUnpad(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0 || buffer.length % 16 !== 0) {
    throw fail('ca_response_padding_invalid');
  }
  let cursor = buffer.length - 1;
  while (cursor >= 0 && buffer[cursor] === 0) cursor -= 1;
  if (cursor < 0 || buffer[cursor] !== 0x80) throw fail('ca_response_padding_invalid');
  return buffer.subarray(0, cursor);
}

function aesCipherName(key, mode) {
  if (![16, 24, 32].includes(key.length) || !['ecb', 'cbc'].includes(mode)) {
    throw fail('ca_aes_key_invalid');
  }
  return `aes-${key.length * 8}-${mode}`;
}

function aesEcbBlock(key, block) {
  if (!Buffer.isBuffer(block) || block.length !== 16) throw fail('ca_aes_block_invalid');
  const cipher = crypto.createCipheriv(aesCipherName(key, 'ecb'), key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function shiftCmacSubkey(block) {
  const output = Buffer.alloc(16);
  let carry = 0;
  for (let index = 15; index >= 0; index -= 1) {
    const value = block[index];
    output[index] = ((value << 1) & 0xff) | carry;
    carry = (value & 0x80) === 0 ? 0 : 1;
  }
  if ((block[0] & 0x80) !== 0) output[15] ^= 0x87;
  return output;
}

function xorBlock(left, right) {
  const output = Buffer.alloc(16);
  for (let index = 0; index < 16; index += 1) output[index] = left[index] ^ right[index];
  return output;
}

function aesCmac(key, message) {
  if (!Buffer.isBuffer(message)) throw fail('ca_cmac_message_invalid');
  const zero = Buffer.alloc(16);
  const subkey1 = shiftCmacSubkey(aesEcbBlock(key, zero));
  const subkey2 = shiftCmacSubkey(subkey1);
  const complete = message.length > 0 && message.length % 16 === 0;
  const blockCount = Math.max(1, Math.ceil(message.length / 16));
  const lastOffset = (blockCount - 1) * 16;
  let last;
  if (complete) {
    last = xorBlock(message.subarray(lastOffset, lastOffset + 16), subkey1);
  } else {
    const partial = Buffer.alloc(16);
    message.subarray(lastOffset).copy(partial);
    partial[message.length - lastOffset] = 0x80;
    last = xorBlock(partial, subkey2);
    partial.fill(0);
  }
  let state = Buffer.alloc(16);
  for (let index = 0; index < blockCount - 1; index += 1) {
    const next = aesEcbBlock(key, xorBlock(state, message.subarray(index * 16, index * 16 + 16)));
    state.fill(0);
    state = next;
  }
  const result = aesEcbBlock(key, xorBlock(state, last));
  zero.fill(0);
  subkey1.fill(0);
  subkey2.fill(0);
  last.fill(0);
  state.fill(0);
  return result;
}

function deriveSessionKey(sharedSecret, keyLength, mode) {
  if (!Buffer.isBuffer(sharedSecret) || sharedSecret.length < 16 ||
      ![128, 192, 256].includes(keyLength) || ![1, 2].includes(mode)) {
    throw fail('ca_kdf_input_invalid');
  }
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(mode);
  const algorithm = keyLength === 128 ? 'sha1' : 'sha256';
  const digest = crypto.createHash(algorithm)
    .update(sharedSecret)
    .update(counter)
    .digest();
  const key = Buffer.from(digest.subarray(0, keyLength / 8));
  digest.fill(0);
  counter.fill(0);
  return key;
}

function sscBytes(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function paddedSSC(value) {
  return Buffer.concat([Buffer.alloc(8), sscBytes(value)]);
}

function protectGetChallenge(ksMac) {
  const header = isoPad(Buffer.from([0x0c, 0x84, 0x00, 0x00]));
  const do97 = Buffer.from([0x97, 0x01, 0x08]);
  const macInput = isoPad(Buffer.concat([paddedSSC(1), header, do97]));
  const mac = aesCmac(ksMac, macInput).subarray(0, 8);
  const do8e = Buffer.concat([Buffer.from([0x8e, 0x08]), mac]);
  const protectedData = Buffer.concat([do97, do8e]);
  const apdu = Buffer.concat([
    Buffer.from([0x0c, 0x84, 0x00, 0x00, protectedData.length]),
    protectedData,
    Buffer.from([0x00]),
  ]);
  header.fill(0);
  macInput.fill(0);
  return apdu;
}

function parseProtectedResponse(data) {
  let offset = 0;
  let do87 = null;
  if (data[offset] === 0x87) {
    do87 = readTLV(data, offset);
    offset = do87.end;
  }
  const do99 = readTLV(data, offset);
  offset = do99.end;
  const do8e = readTLV(data, offset);
  offset = do8e.end;
  if (!do87 || !oneByteTag(do87, 0x87) || do87.content.length < 17 ||
      do87.content[0] !== 0x01 || (do87.content.length - 1) % 16 !== 0 ||
      !oneByteTag(do99, 0x99) || do99.content.length !== 2 ||
      !oneByteTag(do8e, 0x8e) || do8e.content.length !== 8 ||
      offset !== data.length) {
    throw fail('ca_response_structure_invalid');
  }
  return { do87, do99, do8e };
}

function verifyProtectedResponse({ data, sw1, sw2, ksEnc, ksMac }) {
  if (!Buffer.isBuffer(data) || data.length < 32 ||
      data.length > MAX_PROTECTED_RESPONSE_BYTES ||
      !Number.isInteger(sw1) || !Number.isInteger(sw2) ||
      sw1 !== 0x90 || sw2 !== 0x00) {
    throw fail('ca_response_outer_status_invalid');
  }
  const { do87, do99, do8e } = parseProtectedResponse(data);
  const macInput = isoPad(Buffer.concat([paddedSSC(2), do87.raw, do99.raw]));
  const expectedMac = aesCmac(ksMac, macInput).subarray(0, 8);
  if (!crypto.timingSafeEqual(expectedMac, do8e.content)) {
    macInput.fill(0);
    throw fail('ca_response_mac_invalid');
  }
  macInput.fill(0);
  if (do99.content[0] !== 0x90 || do99.content[1] !== 0x00) {
    throw fail('ca_response_inner_status_invalid');
  }
  const ivInput = paddedSSC(2);
  const iv = aesEcbBlock(ksEnc, ivInput);
  ivInput.fill(0);
  const decipher = crypto.createDecipheriv(aesCipherName(ksEnc, 'cbc'), ksEnc, iv);
  decipher.setAutoPadding(false);
  const plaintext = Buffer.concat([
    decipher.update(do87.content.subarray(1)),
    decipher.final(),
  ]);
  iv.fill(0);
  try {
    const challenge = isoUnpad(plaintext);
    if (challenge.length !== 8) throw fail('ca_response_challenge_invalid');
    return Buffer.from(challenge);
  } finally {
    plaintext.fill(0);
  }
}

function rawEphemeralPublicKey(publicKey, namedCurve) {
  const curve = CURVES[namedCurve];
  const jwk = publicKey.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== curve.jwk ||
      typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw fail('ca_ephemeral_public_key_invalid');
  }
  const x = strictBase64Url(jwk.x, curve.coordinateBytes, 'ca_ephemeral_x');
  const y = strictBase64Url(jwk.y, curve.coordinateBytes, 'ca_ephemeral_y');
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

function encodeTokenPayload(input) {
  const contributor = uuidToBytes(input.contributorId);
  const documentChallenge = strictBase64Url(
    input.documentChallengeId, 16, 'ca_document_challenge_id'
  );
  const attestKey = strictBase64(input.attestKeyId, 32, 'ca_attest_key');
  if (attestKey.length !== 32) throw fail('ca_attest_key_invalid');
  const session = uuidToBytes(input.sessionId);
  const dg14Hash = Buffer.from(input.dg14Hash, 'hex');
  if (dg14Hash.length !== 32 || dg14Hash.toString('hex') !== input.dg14Hash) {
    throw fail('ca_dg14_hash_invalid');
  }
  const payload = Buffer.alloc(1 + 16 + 8 + 16 + 16 + 32 + 32 + 1 + 4 + 2 + 1 +
    input.ksEnc.length + 1 + input.ksMac.length + 8);
  let offset = 0;
  payload[offset] = TOKEN_VERSION; offset += 1;
  session.copy(payload, offset); offset += 16;
  payload.writeBigUInt64BE(BigInt(input.expiresAt), offset); offset += 8;
  contributor.copy(payload, offset); offset += 16;
  documentChallenge.copy(payload, offset); offset += 16;
  attestKey.copy(payload, offset); offset += 32;
  dg14Hash.copy(payload, offset); offset += 32;
  payload[offset] = input.protocol.code; offset += 1;
  payload.writeUInt32BE(input.keyId == null ? 0xffffffff : input.keyId, offset); offset += 4;
  payload.writeUInt16BE(input.protocol.keyLength, offset); offset += 2;
  payload[offset] = input.ksEnc.length; offset += 1;
  input.ksEnc.copy(payload, offset); offset += input.ksEnc.length;
  payload[offset] = input.ksMac.length; offset += 1;
  input.ksMac.copy(payload, offset); offset += input.ksMac.length;
  sscBytes(1).copy(payload, offset);
  documentChallenge.fill(0);
  attestKey.fill(0);
  dg14Hash.fill(0);
  return payload;
}

function decodeTokenPayload(payload) {
  const minimum = 1 + 16 + 8 + 16 + 16 + 32 + 32 + 1 + 4 + 2 + 1 + 16 + 1 + 16 + 8;
  if (!Buffer.isBuffer(payload) || payload.length < minimum) throw fail('ca_token_payload_invalid');
  let offset = 0;
  if (payload[offset] !== TOKEN_VERSION) throw fail('ca_token_version_invalid');
  offset += 1;
  const sessionId = bytesToUuid(payload.subarray(offset, offset + 16)); offset += 16;
  const expiresAt = Number(payload.readBigUInt64BE(offset)); offset += 8;
  const contributorId = bytesToUuid(payload.subarray(offset, offset + 16)); offset += 16;
  const documentChallengeId = payload.subarray(offset, offset + 16).toString('base64url'); offset += 16;
  const attestKeyId = payload.subarray(offset, offset + 32).toString('base64'); offset += 32;
  const dg14Hash = payload.subarray(offset, offset + 32).toString('hex'); offset += 32;
  const protocolCode = payload[offset]; offset += 1;
  const protocol = CA_PROTOCOLS_BY_CODE[protocolCode];
  if (!protocol) throw fail('ca_token_protocol_invalid');
  const encodedKeyId = payload.readUInt32BE(offset); offset += 4;
  const keyId = encodedKeyId === 0xffffffff ? null : encodedKeyId;
  const keyLength = payload.readUInt16BE(offset); offset += 2;
  if (keyLength !== protocol.keyLength) throw fail('ca_token_key_length_invalid');
  const encLength = payload[offset]; offset += 1;
  if (encLength !== keyLength / 8 || offset + encLength > payload.length) {
    throw fail('ca_token_key_invalid');
  }
  const ksEnc = Buffer.from(payload.subarray(offset, offset + encLength)); offset += encLength;
  const macLength = payload[offset]; offset += 1;
  if (macLength !== keyLength / 8 || offset + macLength + 8 !== payload.length) {
    ksEnc.fill(0);
    throw fail('ca_token_key_invalid');
  }
  const ksMac = Buffer.from(payload.subarray(offset, offset + macLength)); offset += macLength;
  const ssc = payload.readBigUInt64BE(offset);
  if (ssc !== 1n) {
    ksEnc.fill(0);
    ksMac.fill(0);
    throw fail('ca_token_ssc_invalid');
  }
  return {
    sessionId, expiresAt, contributorId, documentChallengeId, attestKeyId,
    dg14Hash, protocol, keyId, ksEnc, ksMac,
  };
}

function createDocumentCA(
  sealingKey,
  {
    ttlMs = TOKEN_TTL_MS,
    receiptTtlMs = RECEIPT_TTL_MS,
    now = () => Date.now(),
  } = {}
) {
  if (!Buffer.isBuffer(sealingKey) || sealingKey.length !== 32) {
    throw fail('ca_sealing_key_invalid');
  }
  if (!Number.isInteger(ttlMs) || ttlMs < 30_000 || ttlMs > 5 * 60 * 1000 ||
      !Number.isInteger(receiptTtlMs) ||
      receiptTtlMs < 60_000 ||
      receiptTtlMs > 5 * 60 * 1000 ||
      typeof now !== 'function') {
    throw fail('ca_configuration_invalid');
  }
  const key = Buffer.from(sealingKey);

  function seal(payload) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(TOKEN_AAD);
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([Buffer.from([TOKEN_VERSION]), nonce, ciphertext, tag])
      .toString('base64url');
  }

  function open(token) {
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{100,1024}$/.test(token)) {
      throw fail('ca_token_invalid');
    }
    const raw = Buffer.from(token, 'base64url');
    if (raw.toString('base64url') !== token || raw.length < 1 + 12 + 16 ||
        raw[0] !== TOKEN_VERSION) {
      raw.fill(0);
      throw fail('ca_token_invalid');
    }
    const nonce = raw.subarray(1, 13);
    const ciphertext = raw.subarray(13, raw.length - 16);
    const tag = raw.subarray(raw.length - 16);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
      decipher.setAAD(TOKEN_AAD);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw fail('ca_token_invalid');
    } finally {
      raw.fill(0);
    }
  }

  return Object.freeze({
    start({ rawDG14, contributorId, attestKeyId, documentChallengeId }) {
      const dg14 = Buffer.isBuffer(rawDG14) ? Buffer.from(rawDG14) :
        strictBase64(rawDG14, MAX_DG14_BYTES, 'ca_dg14');
      let sharedSecret;
      let ksEnc;
      let ksMac;
      let payload;
      try {
        const candidate = parseDG14(dg14)[0];
        const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
          namedCurve: candidate.namedCurve,
        });
        sharedSecret = crypto.diffieHellman({
          privateKey,
          publicKey: candidate.publicKey,
        });
        ksEnc = deriveSessionKey(sharedSecret, candidate.keyLength, 1);
        ksMac = deriveSessionKey(sharedSecret, candidate.keyLength, 2);
        const ephemeralPublicKey = rawEphemeralPublicKey(publicKey, candidate.namedCurve);
        const protectedCommand = protectGetChallenge(ksMac);
        const sessionId = crypto.randomUUID();
        const expiresAt = now() + ttlMs;
        const dg14Hash = crypto.createHash('sha256').update(dg14).digest('hex');
        payload = encodeTokenPayload({
          sessionId,
          expiresAt,
          contributorId,
          attestKeyId,
          documentChallengeId,
          dg14Hash,
          protocol: candidate,
          keyId: candidate.keyId,
          ksEnc,
          ksMac,
        });
        return {
          sessionId,
          expiresAt: new Date(expiresAt).toISOString(),
          dg14Hash,
          option: {
            keyId: candidate.keyId,
            protocolOID: candidate.oid,
            publicKeyOID: ID_PK_ECDH,
            keyAgreementAlgorithm: 'ECDH',
            cipherAlgorithm: 'AES',
            keyLength: candidate.keyLength,
          },
          ephemeralPublicKey: ephemeralPublicKey.toString('base64'),
          protectedCommand: protectedCommand.toString('base64'),
          token: seal(payload),
        };
      } finally {
        dg14.fill(0);
        if (sharedSecret) sharedSecret.fill(0);
        if (ksEnc) ksEnc.fill(0);
        if (ksMac) ksMac.fill(0);
        if (payload) payload.fill(0);
      }
    },

    complete({
      token, contributorId, attestKeyId, documentChallengeId,
      responseData, sw1, sw2,
    }) {
      const payload = open(token);
      let session;
      let response;
      try {
        session = decodeTokenPayload(payload);
        if (session.expiresAt < now()) throw fail('ca_token_expired');
        if (session.contributorId !== contributorId ||
            session.attestKeyId !== attestKeyId ||
            session.documentChallengeId !== documentChallengeId) {
          throw fail('ca_token_binding_invalid');
        }
        response = strictBase64(
          responseData, MAX_PROTECTED_RESPONSE_BYTES, 'ca_protected_response'
        );
        const challenge = verifyProtectedResponse({
          data: response,
          sw1,
          sw2,
          ksEnc: session.ksEnc,
          ksMac: session.ksMac,
        });
        challenge.fill(0);
        return {
          sessionId: session.sessionId,
          contributorId: session.contributorId,
          attestKeyId: session.attestKeyId,
          documentChallengeId: session.documentChallengeId,
          dg14Hash: session.dg14Hash,
          protocolOID: session.protocol.oid,
          keyId: session.keyId,
          // The encrypted relay token has already served its purpose and may
          // expire quickly. The minimal DB receipt must remain available long
          // enough for the user to finish the subsequent liveness step.
          expiresAt: new Date(now() + receiptTtlMs).toISOString(),
        };
      } finally {
        payload.fill(0);
        if (response) response.fill(0);
        if (session?.ksEnc) session.ksEnc.fill(0);
        if (session?.ksMac) session.ksMac.fill(0);
      }
    },
  });
}

module.exports = {
  createDocumentCA,
  parseDG14,
  _test: Object.freeze({
    aesCmac,
    deriveSessionKey,
    isoPad,
    paddedSSC,
    protectGetChallenge,
  }),
};
