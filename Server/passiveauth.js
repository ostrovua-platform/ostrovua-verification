// ═══════════════════════════════════════════════════════════════════
//  Passive Authentication (ICAO 9303 Part 11) — серверна перевірка
//  справжності даних чипа біометричного документа.
//
//  Що перевіряється (усе — на сервері, клієнту НЕ довіряємо):
//   1. SOD (EF.SOD з чипа) — це CMS SignedData. Перевіряємо цілісність
//      підпису Document Signer'а (openssl cms -verify).
//   2. Ланцюжок довіри: Document Signer Certificate (DSC) → CSCA
//      (Country Signing CA). Корені — ЛИШЕ запінені українські CSCA
//      (csca_ua.pem, побудований fetch_masterlist.sh з пінами,
//      звіреними за двома незалежними джерелами: BSI + ICAO PKD).
//   3. Хеші груп даних: клієнт надсилає хеші DG1/DG2, які він реально
//      прочитав і з якими звіряв обличчя. Порівнюємо з хешами,
//      ПІДПИСАНИМИ ДЕРЖАВОЮ всередині SOD.
//
//  Що це НЕ ловить (чесно): точну копію чипа (клон з тим самим SOD).
//  Проти клонів існує Chip/Active Authentication — окремий етап.
//
//  ПРИВАТНІСТЬ: SOD не містить імені, номера, дати народження чи фото —
//  лише хеші груп даних, сертифікат і підпис. У protocol v6 сирі DG1/DG2
//  тимчасово надходять для серверного hashing; вони не пишуться у temp-файли
//  або БД, а mutable buffers затираються власником маршруту після рішення.
//  SOD перевіряється у тимчасовій теці й одразу видаляється.
//
//  РЕСУРСИ (аудит P1-05): усі виклики openssl — асинхронні (execFile),
//  кількість одночасних перевірок обмежена семафором, розмір входу —
//  жорстким лімітом ДО декодування.
// ═══════════════════════════════════════════════════════════════════
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFile } = require('child_process');

const MASTERLIST = process.env.CSCA_MASTERLIST || '/app/csca/csca_ua.pem';
// Каталог пошуку DSC для документів, які не вкладають signer certificate у
// SOD. Наявність сертифіката тут НЕ надає довіри: після пошуку завжди окремо
// перевіряються ланцюжок DSC→CSCA та revocation/active snapshot.
//
// CSCA_DSC лишено лише як безпечний fallback для старих deployment: у такому
// режимі lookup та active вказують на той самий, вузький active bundle.
const ACTIVE_DSC_BUNDLE =
  process.env.CSCA_ACTIVE_DSC || process.env.CSCA_DSC || '/app/csca/dsc_ua.pem';
const DSC_LOOKUP_BUNDLE =
  process.env.CSCA_DSC_LOOKUP || ACTIVE_DSC_BUNDLE;
const CRL_FILE = process.env.CSCA_CRL || '/app/csca/csca_ua.crl.pem';
// Якщо держава не публікує CRL для конкретного нового CSCA, приймаємо DSC
// лише з адміністративно імпортованого official active-all snapshot. Snapshot
// швидко протухає: це обмежує revocation window і не перетворює bundle на
// безстроковий trust store.
const ACTIVE_DSC_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const ACTIVE_DSC_MIN_CERTIFICATES = 90;
// Вимкнення перевірки строку дії DSC — FAIL-CLOSED (аудит P1-01):
// дозволено ЛИШЕ при ЯВНОМУ APP_ENV=development. Будь-яка опечатка
// в APP_ENV трактується як production і НЕ вмикає no_check_time.
const NO_CHECK_TIME =
  process.env.PA_NO_CHECK_TIME === '1' && process.env.APP_ENV === 'development';
const REQUIRE_UA = process.env.PA_REQUIRE_UA !== '0';

const MAX_SOD_B64_CHARS = 96 * 1024; // ліміт ДО decode (реальний SOD ~2-7 КБ b64)
const MAX_SOD_BYTES = 64 * 1024;
const MAX_DG1_BYTES = 128 * 1024;
const MAX_DG2_BYTES = 2 * 1024 * 1024;
const MAX_DG14_BYTES = 128 * 1024;
const MAX_DG15_BYTES = 128 * 1024;
const OPENSSL_TIMEOUT_MS = 5000;
const MAX_CONCURRENT = 2;            // семафор: не блокуємо auth-сервіс

// ── Семафор з ОБМЕЖЕНОЮ чергою (аудит P1-07) ────────────────────────
// Черга очікування не безмежна: під навантаженням зайві запити
// відхиляються (fail-fast), а не накопичуються в памʼяті.
const MAX_WAITERS = 64;
let running = 0;
const waiters = [];
function acquire() {
  if (running < MAX_CONCURRENT) { running++; return Promise.resolve(); }
  if (waiters.length >= MAX_WAITERS) {
    return Promise.reject(new Error('PA overloaded'));
  }
  return new Promise((resolve) => waiters.push(resolve));
}
function release() {
  const next = waiters.shift();
  if (next) next(); else running--;
}

function openssl(args) {
  return new Promise((resolve, reject) => {
    execFile('openssl', args, {
      timeout: OPENSSL_TIMEOUT_MS,
      maxBuffer: 1024 * 1024,
      encoding: 'buffer',
    }, (err, stdout, stderr) => {
      if (err) { err.stderr = stderr ? stderr.toString() : ''; reject(err); }
      else resolve(stdout);
    });
  });
}

function classifyCMSFailure(stderr) {
  const detail = String(stderr || '').toLowerCase();
  if (detail.includes('signer certificate not found')) {
    // Валідність підпису ще неможливо визначити: у SOD немає DSC, а
    // адміністративний ICAO PKD bundle не покриває цього підписанта.
    return { status: 'unavailable', reason: 'dsc_not_found' };
  }
  if (detail.includes('unsupported') || detail.includes('unknown digest') ||
      detail.includes('unknown cipher') || detail.includes('fetch failed')) {
    return { status: 'unavailable', reason: 'cms_algorithm_unsupported' };
  }
  if (detail.includes('error reading smime content info') ||
      detail.includes('asn1 encoding routines') ||
      detail.includes('content type not signed data') ||
      detail.includes('no content')) {
    return { status: 'failed', reason: 'sod_cms_malformed' };
  }
  return { status: 'failed', reason: 'cms_signature_invalid' };
}

function classifyChainFailure(stderr) {
  const detail = String(stderr || '').toLowerCase();
  if (detail.includes('certificate revoked')) {
    return { status: 'failed', reason: 'dsc_revoked' };
  }
  if (detail.includes('unable to get certificate crl') ||
      detail.includes('unable to get crl') ||
      detail.includes('crl has expired') ||
      detail.includes('crl is not yet valid')) {
    return { status: 'unavailable', reason: 'crl_unavailable' };
  }
  if (detail.includes('explicit ecc parameters')) {
    // OpenSSL 3 rejects this legacy encoding before signature validation.
    // Some current UA DSCs use explicit Brainpool parameters, so this is a
    // compatibility limitation, not evidence of a forged document.
    return { status: 'unavailable', reason: 'dsc_legacy_ec_unsupported' };
  }
  if (detail.includes('unable to get local issuer certificate') ||
      detail.includes('unable to verify the first certificate')) {
    return { status: 'unavailable', reason: 'csca_not_found' };
  }
  return { status: 'failed', reason: 'csca_chain_failed' };
}

async function containsPEMCertificate(file) {
  try {
    return (await fs.promises.readFile(file, 'utf8')).includes('-----BEGIN CERTIFICATE-----');
  } catch {
    return false;
  }
}

async function containsPEMCRL(file) {
  try {
    return (await fs.promises.readFile(file, 'utf8')).includes('-----BEGIN X509 CRL-----');
  } catch {
    return false;
  }
}

let activeDscCache = null;
async function loadFreshActiveDSCBundle(
  bundlePath = ACTIVE_DSC_BUNDLE,
  minimumCertificates = ACTIVE_DSC_MIN_CERTIFICATES
) {
  const stat = await fs.promises.stat(bundlePath);
  if (activeDscCache && activeDscCache.mtimeMs === stat.mtimeMs &&
      activeDscCache.size === stat.size && activeDscCache.path === bundlePath) {
    if (Date.now() - activeDscCache.generatedAt > ACTIVE_DSC_MAX_AGE_MS) {
      throw new Error('active_dsc_stale');
    }
    return activeDscCache.fingerprints;
  }
  if (stat.size <= 0 || stat.size > 4 * 1024 * 1024) {
    throw new Error('active_dsc_size_invalid');
  }
  const bundle = await fs.promises.readFile(bundlePath, 'utf8');
  const generatedMatch = bundle.match(/^# generated_at=([^\r\n]+)$/m);
  const sourceMatch = bundle.match(/^# source_sha256=([0-9a-f]{64})$/m);
  if (!generatedMatch || !sourceMatch) throw new Error('active_dsc_provenance_missing');
  const generatedAt = Date.parse(generatedMatch[1]);
  const age = Date.now() - generatedAt;
  if (!Number.isFinite(generatedAt) || age < -5 * 60 * 1000 || age > ACTIVE_DSC_MAX_AGE_MS) {
    throw new Error('active_dsc_stale');
  }
  const blocks = bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  if (blocks.length < minimumCertificates) {
    throw new Error('active_dsc_too_small');
  }
  const fingerprints = new Set();
  for (const block of blocks) {
    const cert = new crypto.X509Certificate(block);
    if (cert.ca) throw new Error('active_dsc_contains_ca');
    fingerprints.add(cert.fingerprint256.replace(/:/g, '').toLowerCase());
  }
  if (fingerprints.size !== blocks.length) throw new Error('active_dsc_duplicates');
  activeDscCache = {
    path: bundlePath,
    mtimeMs: stat.mtimeMs,
    size: stat.size,
    generatedAt,
    fingerprints,
  };
  return fingerprints;
}

async function requireFreshActiveDSC(
  signerPath,
  bundlePath = ACTIVE_DSC_BUNDLE,
  minimumCertificates = ACTIVE_DSC_MIN_CERTIFICATES
) {
  let fingerprints;
  try {
    fingerprints = await loadFreshActiveDSCBundle(bundlePath, minimumCertificates);
  } catch (error) {
    console.error(`[PA] active DSC bundle unavailable reason=${error.message}`);
    return { status: 'unavailable', reason: 'active_dsc_unavailable' };
  }
  let signer;
  try {
    signer = new crypto.X509Certificate(await fs.promises.readFile(signerPath));
  } catch {
    return { status: 'failed', reason: 'dsc_malformed' };
  }
  const signerFingerprint = signer.fingerprint256.replace(/:/g, '').toLowerCase();
  if (!fingerprints.has(signerFingerprint)) {
    return { status: 'failed', reason: 'dsc_not_active' };
  }
  return null;
}

// ── Мінімальний DER/TLV-парсер (лише читання, без залежностей) ──────
// Аудит P1-04: перевіряємо повне споживання буфера, дублікати DG,
// довжину хешу за алгоритмом. Це не заміна зрілої ASN.1-бібліотеки —
// профіль обмежено LDSSecurityObject; фаззинг — у плані тестів.

function tlv(buf, off) {
  let p = off;
  if (p >= buf.length) throw new Error('DER: несподіваний кінець');
  const first = buf[p++];
  let tagNum = first & 0x1f;
  if (tagNum === 0x1f) {
    tagNum = 0;
    let b;
    do {
      if (p >= buf.length) throw new Error('DER: обірваний тег');
      b = buf[p++];
      tagNum = (tagNum << 7) | (b & 0x7f);
    } while (b & 0x80);
  }
  if (p >= buf.length) throw new Error('DER: немає довжини');
  let lenByte = buf[p++];
  let len;
  if (lenByte < 0x80) {
    len = lenByte;
  } else {
    const n = lenByte & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: заборонена довжина (BER?)');
    len = 0;
    for (let i = 0; i < n; i++) {
      if (p >= buf.length) throw new Error('DER: обірвана довжина');
      len = len * 256 + buf[p++];
    }
    if (len < 0x80) throw new Error('DER: неканонічна довжина');
  }
  if (p + len > buf.length) throw new Error('DER: довжина за межами буфера');
  return { firstByte: first, tagNum, cStart: p, cEnd: p + len, end: p + len };
}

function children(buf, node) {
  const out = [];
  let p = node.cStart;
  while (p < node.cEnd) {
    const t = tlv(buf, p);
    out.push(t);
    p = t.end;
  }
  return out;
}

function decodeOID(buf, node) {
  const bytes = buf.slice(node.cStart, node.cEnd);
  if (bytes.length === 0) return '';
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = (v << 7) | (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}

const HASH_OIDS = {
  '1.3.14.3.2.26': { name: 'sha1', bytes: 20 },
  '2.16.840.1.101.3.4.2.4': { name: 'sha224', bytes: 28 },
  '2.16.840.1.101.3.4.2.1': { name: 'sha256', bytes: 32 },
  '2.16.840.1.101.3.4.2.2': { name: 'sha384', bytes: 48 },
  '2.16.840.1.101.3.4.2.3': { name: 'sha512', bytes: 64 },
};

/// LDSSecurityObject ::= SEQUENCE {
///   version INTEGER, hashAlgorithm AlgorithmIdentifier,
///   dataGroupHashValues SEQUENCE OF { dgNumber INTEGER, dgHash OCTET STRING } }
function parseLDSSecurityObject(buf) {
  const root = tlv(buf, 0);
  if (root.firstByte !== 0x30) throw new Error('LDS: очікував SEQUENCE');
  if (root.end !== buf.length) throw new Error('LDS: зайві байти після структури');
  const kids = children(buf, root);
  if (kids.length < 3) throw new Error('LDS: замало елементів');

  const algKids = children(buf, kids[1]);
  if (!algKids.length || algKids[0].firstByte !== 0x06) throw new Error('LDS: немає OID алгоритму');
  const oid = decodeOID(buf, algKids[0]);
  const alg = HASH_OIDS[oid];
  if (!alg) throw new Error(`LDS: невідомий алгоритм хешу ${oid}`);

  const dgHashes = {};
  for (const entry of children(buf, kids[2])) {
    const pair = children(buf, entry);
    if (pair.length < 2 || pair[0].firstByte !== 0x02 || pair[1].firstByte !== 0x04) continue;
    let dgNum = 0;
    for (let i = pair[0].cStart; i < pair[0].cEnd; i++) dgNum = dgNum * 256 + buf[i];
    if (dgNum < 1 || dgNum > 16) throw new Error(`LDS: неприпустимий номер DG ${dgNum}`);
    if (dgHashes[dgNum] !== undefined) throw new Error(`LDS: дубльований DG${dgNum}`);
    const h = buf.slice(pair[1].cStart, pair[1].cEnd);
    if (h.length !== alg.bytes) throw new Error(`LDS: довжина хешу DG${dgNum} не відповідає ${alg.name}`);
    dgHashes[dgNum] = h.toString('hex');
  }
  if (!dgHashes[1] || !dgHashes[2]) throw new Error('LDS: немає хешів DG1/DG2');
  return { algorithm: alg.name, dgHashes };
}

/// EF.SOD на чипі загорнутий у application-тег 0x77 — знімаємо.
function stripIcaoWrapper(buf) {
  if (buf[0] !== 0x77) return buf;
  const t = tlv(buf, 0);
  if (t.end !== buf.length) throw new Error('SOD: зайві байти після 0x77-обгортки');
  return buf.slice(t.cStart, t.cEnd);
}

function safeHexEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string' ||
      !/^[0-9a-f]+$/i.test(left) || !/^[0-9a-f]+$/i.test(right) ||
      left.length !== right.length) return false;
  return crypto.timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
}

function validateRawDataGroups(rawDataGroups) {
  if (!rawDataGroups || typeof rawDataGroups !== 'object' || Array.isArray(rawDataGroups)) {
    throw new Error('raw_dg_shape_invalid');
  }
  const names = Object.keys(rawDataGroups).sort();
  if (!names.includes('dg1') || !names.includes('dg2') ||
      names.some((name) => !['dg1', 'dg2', 'dg14', 'dg15'].includes(name))) {
    throw new Error('raw_dg_shape_invalid');
  }
  const { dg1, dg2, dg14, dg15 } = rawDataGroups;
  if (!Buffer.isBuffer(dg1) || dg1.length === 0 || dg1.length > MAX_DG1_BYTES ||
      !Buffer.isBuffer(dg2) || dg2.length === 0 || dg2.length > MAX_DG2_BYTES ||
      (dg14 !== undefined &&
        (!Buffer.isBuffer(dg14) || dg14.length === 0 || dg14.length > MAX_DG14_BYTES)) ||
      (dg15 !== undefined &&
        (!Buffer.isBuffer(dg15) || dg15.length === 0 || dg15.length > MAX_DG15_BYTES))) {
    throw new Error('raw_dg_size_invalid');
  }
  return { dg1, dg2, ...(dg14 ? { dg14 } : {}), ...(dg15 ? { dg15 } : {}) };
}

function hashRawDataGroups(rawDataGroups, algorithm) {
  const groups = validateRawDataGroups(rawDataGroups);
  if (!Object.values(HASH_OIDS).some((entry) => entry.name === algorithm)) {
    throw new Error('raw_dg_hash_algorithm_invalid');
  }
  return Object.fromEntries(Object.entries(groups).map(([name, value]) => [
    name,
    crypto.createHash(algorithm).update(value).digest('hex'),
  ]));
}

// ── Головна перевірка (async) ───────────────────────────────────────
//
// Повертає (НІКОЛИ не кидає):
//   { status: 'passed'|'failed'|'unavailable', reason, algorithm, issuer }
//
// 'failed'      — SOD битий/підроблений/не збігаються хеші → ВІДМОВА.
// 'unavailable' — проблема КОНФІГУРАЦІЇ сервера (немає masterlist).
async function verifySOD({ sodBase64, dgHashes, rawDataGroups }) {
  try {
    await acquire();
  } catch {
    // Черга перевантажена → тимчасово недоступно (fail-closed, не 500)
    return { status: 'unavailable', reason: 'overloaded' };
  }
  let tmp;
  try {
    if (typeof sodBase64 !== 'string' || !sodBase64 || sodBase64.length > MAX_SOD_B64_CHARS) {
      return { status: 'failed', reason: 'sod_missing_or_oversized' };
    }
    if (sodBase64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(sodBase64)) {
      return { status: 'failed', reason: 'sod_malformed' };
    }
    let sod;
    try {
      sod = Buffer.from(sodBase64, 'base64');
    } catch {
      return { status: 'failed', reason: 'sod_malformed' };
    }
    if (!sod.length || sod.length > MAX_SOD_BYTES) {
      return { status: 'failed', reason: 'sod_malformed' };
    }

    let cms;
    try {
      cms = stripIcaoWrapper(sod);
    } catch {
      return { status: 'failed', reason: 'sod_malformed' };
    }

    tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'pa-'));
    const cmsPath = path.join(tmp, 'sod.der');
    const contentPath = path.join(tmp, 'lds.der');
    const signerPath = path.join(tmp, 'signer.pem');
    const certsPath = path.join(tmp, 'certs.pem');
    await fs.promises.writeFile(cmsPath, cms);

    // 1. Цілісність підпису DSC над вмістом (signedAttrs.messageDigest
    //    звіряється з eContent, сам підпис — з сертифікатом підписанта).
    try {
      const verifyArgs = [
        'cms', '-verify', '-inform', 'DER', '-in', cmsPath,
        '-binary', '-noverify',
        '-out', contentPath,
        '-signer', signerPath,
        '-certsout', certsPath,
      ];
      // Наш зібраний список DSC — щоб знайти підписанта, якщо його немає
      // у SOD. Не впливає на довіру: ланцюг DSC→CSCA перевіряється в кроці 3.
      if (await containsPEMCertificate(DSC_LOOKUP_BUNDLE)) {
        verifyArgs.push('-certfile', DSC_LOOKUP_BUNDLE);
      }
      await openssl(verifyArgs);
    } catch (e) {
      const failure = classifyCMSFailure(e.stderr || e.message);
      // Логуємо стабільний код без SOD, сертифікатів та персональних даних.
      console.error(`[PA] cms verify failed reason=${failure.reason}`);
      return failure;
    }

    // 2. Хеші DG1/DG2, ПІДПИСАНІ державою, проти хешів клієнта.
    let lds;
    try {
      lds = parseLDSSecurityObject(await fs.promises.readFile(contentPath));
    } catch (e) {
      return { status: 'failed', reason: 'lds_parse_failed' };
    }

    let observed;
    if (rawDataGroups !== undefined) {
      try {
        observed = hashRawDataGroups(rawDataGroups, lds.algorithm);
      } catch (e) {
        return { status: 'failed', reason: e.message || 'raw_dg_invalid' };
      }
    } else {
      observed = {};
      for (const [name, number] of Object.entries(
        { dg1: 1, dg2: 2, dg14: 14, dg15: 15 }
      )) {
        const clientHash = dgHashes?.[name]?.[lds.algorithm];
        if (lds.dgHashes[number] && !clientHash) {
          return { status: 'failed', reason: `client_${name}_hash_missing_${lds.algorithm}` };
        }
        if (clientHash) observed[name] = String(clientHash).toLowerCase();
      }
    }
    for (const [name, number] of Object.entries(
      { dg1: 1, dg2: 2, dg14: 14, dg15: 15 }
    )) {
      if (lds.dgHashes[number] && observed[name] === undefined) {
        return { status: 'failed', reason: `${name}_evidence_missing`, algorithm: lds.algorithm };
      }
      if (observed[name] !== undefined &&
          (!lds.dgHashes[number] || !safeHexEqual(observed[name], lds.dgHashes[number]))) {
        return { status: 'failed', reason: `${name}_hash_mismatch`, algorithm: lds.algorithm };
      }
    }

    // 3. Ланцюжок довіри: DSC → запінені CSCA України.
    if (!await containsPEMCertificate(MASTERLIST)) {
      return { status: 'unavailable', reason: 'masterlist_missing', algorithm: lds.algorithm };
    }
    const chainArgs = ['verify', '-purpose', 'any', '-CAfile', MASTERLIST];
    if (NO_CHECK_TIME) chainArgs.push('-no_check_time');
    // Коли DSC знайдено у зовнішньому bundle, certsout може бути
    // порожнім. OpenSSL відхиляє `-untrusted` із порожнім PEM.
    if (await containsPEMCertificate(certsPath)) {
      chainArgs.push('-untrusted', certsPath);
    }
    chainArgs.push(signerPath);
    try {
      // Спочатку окремо доводимо DSC → CSCA. Це не дозволяє помилці
      // «CRL для іншого issuer» маскувати справжню помилку ланцюжка.
      await openssl(chainArgs);
    } catch (e) {
      return { ...classifyChainFailure(e.stderr || e.message), algorithm: lds.algorithm };
    }

    // 3b. Revocation — issuer-aware. Якщо наявна CRL покриває signer,
    // OpenSSL перевіряє її підпис, строк і serial. Якщо bundle містить CRL
    // лише іншого CSCA, OpenSSL повертає unable-to-get-CRL: тоді не
    // вимикаємо revocation глобально, а вимагаємо signer у СВІЖОМУ
    // official active-all snapshot.
    let needsActiveSnapshot = !await containsPEMCRL(CRL_FILE);
    if (!needsActiveSnapshot) {
      const crlArgs = chainArgs.slice(0, -1);
      crlArgs.push('-crl_check', '-CRLfile', CRL_FILE, signerPath);
      try {
        await openssl(crlArgs);
      } catch (e) {
        const failure = classifyChainFailure(e.stderr || e.message);
        if (failure.reason === 'crl_unavailable' &&
            /unable to get (certificate )?crl/i.test(String(e.stderr || e.message))) {
          needsActiveSnapshot = true;
        } else {
          return { ...failure, algorithm: lds.algorithm };
        }
      }
    }
    if (needsActiveSnapshot) {
      const activeFailure = await requireFreshActiveDSC(signerPath);
      if (activeFailure) return { ...activeFailure, algorithm: lds.algorithm };
    }

    // 4. Країна: емітент DSC мусить бути українська CSCA (C=UA).
    let issuer = '';
    try {
      issuer = (await openssl(['x509', '-in', signerPath, '-noout', '-issuer'])).toString();
    } catch { /* ланцюжок уже перевірено */ }
    if (REQUIRE_UA && (!issuer || !/\bC\s*=\s*UA\b/.test(issuer))) {
      return { status: 'failed', reason: 'issuer_not_ukraine', issuer: issuer.trim() };
    }

    return {
      status: 'passed',
      reason: null,
      algorithm: lds.algorithm,
      issuer: issuer.trim() || null,
      // Державно підписаний хеш DG1 — стабільний ідентифікатор
      // ПРИМІРНИКА документа. Використовується ЛИШЕ як вхід HMAC
      // для токена «1 документ = 1 акаунт»; не логувати, не зберігати.
      sodDG1Hash: lds.dgHashes[1],
    };
  } catch {
    return { status: 'failed', reason: 'internal_error' };
  } finally {
    if (tmp) { try { await fs.promises.rm(tmp, { recursive: true, force: true }); } catch { /* noop */ } }
    release();
  }
}

module.exports = {
  verifySOD,
  parseLDSSecurityObject,
  stripIcaoWrapper,
  hashRawDataGroups,
  validateRawDataGroups,
  classifyCMSFailure,
  classifyChainFailure,
  loadFreshActiveDSCBundle,
  requireFreshActiveDSC,
};
