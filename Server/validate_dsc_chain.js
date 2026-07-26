#!/usr/bin/env node
'use strict';

// A deliberately narrow ICAO compatibility verifier.  OpenSSL 3.6 rejects
// otherwise valid DSCs whose EC public key uses explicit curve parameters;
// LibreSSL rejects one official DSC with a malformed, non-critical SAN.  This
// helper does not replace normal PKIX validation.  It is only a fallback for
// those two known parser/policy errors and still requires a current end-entity
// DSC whose signature verifies directly under a pinned CSCA.

const crypto = require('crypto');
const fs = require('fs');

const PEM_CERTIFICATE_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const SHA256_RE = /^[0-9a-f]{64}$/;
const ALLOWED_EC_CURVES = new Set([
  'prime256v1',
  'secp384r1',
  'secp521r1',
  'brainpoolP256r1',
  'brainpoolP384r1',
  'brainpoolP512r1',
]);

class DirectChainError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DirectChainError';
    this.code = code;
  }
}

function fingerprint(certificate) {
  return certificate.fingerprint256.replace(/:/g, '').toLowerCase();
}

function parsePins(text) {
  const pins = new Set();
  for (const [index, rawLine] of String(text).split(/\r?\n/).entries()) {
    const value = rawLine.split('#', 1)[0].trim().toLowerCase().replace(/:/g, '');
    if (!value) continue;
    if (!SHA256_RE.test(value)) {
      throw new DirectChainError('pins_malformed', `invalid SHA-256 pin at line ${index + 1}`);
    }
    pins.add(value);
  }
  if (pins.size === 0) throw new DirectChainError('pins_empty', 'no CSCA pins were provided');
  return pins;
}

function parseCurrentTime(certificate, now, label) {
  const notBefore = Date.parse(certificate.validFrom);
  const notAfter = Date.parse(certificate.validTo);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
    throw new DirectChainError('certificate_time_malformed', `${label} has invalid validity dates`);
  }
  const instant = now.getTime();
  if (instant < notBefore || instant > notAfter) {
    throw new DirectChainError('certificate_not_current', `${label} is outside its validity period`);
  }
}

function parseTrustBundle(caBundlePem, pins, now) {
  const blocks = String(caBundlePem).match(PEM_CERTIFICATE_RE) || [];
  if (blocks.length === 0) {
    throw new DirectChainError('trust_bundle_empty', 'CSCA bundle contains no certificates');
  }

  const roots = [];
  const seen = new Set();
  for (const block of blocks) {
    let root;
    try {
      root = new crypto.X509Certificate(block);
    } catch (error) {
      throw new DirectChainError('trust_certificate_malformed', `cannot parse CSCA: ${error.message}`);
    }
    const rootFingerprint = fingerprint(root);
    if (!pins.has(rootFingerprint)) {
      throw new DirectChainError(
        'trust_certificate_unpinned',
        `CSCA bundle contains unpinned certificate ${rootFingerprint}`,
      );
    }
    if (!root.ca) {
      throw new DirectChainError('trust_certificate_not_ca', `pinned certificate ${rootFingerprint} is not a CA`);
    }
    parseCurrentTime(root, now, `CSCA ${rootFingerprint}`);
    if (!seen.has(rootFingerprint)) {
      roots.push({ certificate: root, fingerprint: rootFingerprint });
      seen.add(rootFingerprint);
    }
  }
  return roots;
}

function assertLeafPublicKeyStrength(leaf) {
  const key = leaf.publicKey;
  const details = key.asymmetricKeyDetails || {};
  if (key.asymmetricKeyType === 'rsa' || key.asymmetricKeyType === 'rsa-pss') {
    if (!Number.isInteger(details.modulusLength) || details.modulusLength < 2048) {
      throw new DirectChainError('dsc_key_too_weak', 'DSC RSA key is shorter than 2048 bits');
    }
    return;
  }
  if (key.asymmetricKeyType === 'ec') {
    if (!ALLOWED_EC_CURVES.has(details.namedCurve)) {
      throw new DirectChainError(
        'dsc_curve_not_allowed',
        `DSC EC curve is not allowed: ${details.namedCurve || 'unknown'}`,
      );
    }
    return;
  }
  throw new DirectChainError(
    'dsc_key_type_not_allowed',
    `DSC public-key type is not allowed: ${key.asymmetricKeyType || 'unknown'}`,
  );
}

function verifyDirectChain({ leafPem, caBundlePem, pinsText, now = new Date() }) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new DirectChainError('time_invalid', 'verification time is invalid');
  }
  const pins = parsePins(pinsText);
  const roots = parseTrustBundle(caBundlePem, pins, now);

  let leaf;
  try {
    leaf = new crypto.X509Certificate(leafPem);
  } catch (error) {
    throw new DirectChainError('dsc_malformed', `cannot parse DSC: ${error.message}`);
  }
  const leafFingerprint = fingerprint(leaf);
  if (pins.has(leafFingerprint) || leaf.ca) {
    throw new DirectChainError('dsc_is_ca', 'the candidate DSC is a CA certificate');
  }
  parseCurrentTime(leaf, now, `DSC ${leafFingerprint}`);
  assertLeafPublicKeyStrength(leaf);

  for (const root of roots) {
    if (leaf.issuer !== root.certificate.subject) continue;
    let issued = false;
    let signatureValid = false;
    try {
      issued = leaf.checkIssued(root.certificate);
      signatureValid = leaf.verify(root.certificate.publicKey);
    } catch {
      continue;
    }
    if (issued && signatureValid) {
      return {
        leafFingerprint,
        issuerFingerprint: root.fingerprint,
      };
    }
  }
  throw new DirectChainError(
    'dsc_signature_invalid',
    `DSC ${leafFingerprint} is not signed directly by a pinned CSCA`,
  );
}

async function verifyDirectChainFiles({ leafPath, caBundlePath, pinsPath }) {
  const [leafPem, caBundlePem, pinsText] = await Promise.all([
    fs.promises.readFile(leafPath),
    fs.promises.readFile(caBundlePath, 'utf8'),
    fs.promises.readFile(pinsPath, 'utf8'),
  ]);
  return verifyDirectChain({ leafPem, caBundlePem, pinsText });
}

async function main() {
  const [leafPath, caBundlePath, pinsPath] = process.argv.slice(2);
  if (!leafPath || !caBundlePath || !pinsPath) {
    console.error('usage: validate_dsc_chain.js LEAF.pem CSCA.pem pins_ua.txt');
    process.exitCode = 2;
    return;
  }
  try {
    const result = await verifyDirectChainFiles({ leafPath, caBundlePath, pinsPath });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const code = error instanceof DirectChainError ? error.code : 'unexpected_error';
    console.error(`${code}: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  DirectChainError,
  assertLeafPublicKeyStrength,
  parsePins,
  verifyDirectChain,
  verifyDirectChainFiles,
};
