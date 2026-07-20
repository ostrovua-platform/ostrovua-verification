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
//  лише хеші груп даних, сертифікат і підпис. Персональні поля документа
//  на сервер як і раніше НЕ передаються. SOD перевіряється у тимчасовій
//  теці й одразу видаляється; у базі лишається тільки результат.
//
//  РЕСУРСИ (аудит P1-05): усі виклики openssl — асинхронні (execFile),
//  кількість одночасних перевірок обмежена семафором, розмір входу —
//  жорстким лімітом ДО декодування.
// ═══════════════════════════════════════════════════════════════════
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const MASTERLIST = process.env.CSCA_MASTERLIST || '/app/csca/csca_ua.pem';
// Вимкнення перевірки строку дії DSC: ЛИШЕ поза production (аудит P1-01).
const NO_CHECK_TIME =
  process.env.PA_NO_CHECK_TIME === '1' && process.env.APP_ENV !== 'production';
const REQUIRE_UA = process.env.PA_REQUIRE_UA !== '0';

const MAX_SOD_B64_CHARS = 96 * 1024; // ліміт ДО decode (реальний SOD ~2-7 КБ b64)
const MAX_SOD_BYTES = 64 * 1024;
const OPENSSL_TIMEOUT_MS = 5000;
const MAX_CONCURRENT = 2;            // семафор: не блокуємо auth-сервіс

// ── Простий семафор ─────────────────────────────────────────────────
let running = 0;
const waiters = [];
function acquire() {
  if (running < MAX_CONCURRENT) { running++; return Promise.resolve(); }
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
    }, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
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

// ── Головна перевірка (async) ───────────────────────────────────────
//
// Повертає (НІКОЛИ не кидає):
//   { status: 'passed'|'failed'|'unavailable', reason, algorithm, issuer }
//
// 'failed'      — SOD битий/підроблений/не збігаються хеші → ВІДМОВА.
// 'unavailable' — проблема КОНФІГУРАЦІЇ сервера (немає masterlist).
async function verifySOD({ sodBase64, dgHashes }) {
  await acquire();
  let tmp;
  try {
    if (typeof sodBase64 !== 'string' || !sodBase64 || sodBase64.length > MAX_SOD_B64_CHARS) {
      return { status: 'failed', reason: 'sod_missing_or_oversized' };
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
      await openssl([
        'cms', '-verify', '-inform', 'DER', '-in', cmsPath,
        '-noverify',
        '-out', contentPath,
        '-signer', signerPath,
        '-certsout', certsPath,
      ]);
    } catch {
      return { status: 'failed', reason: 'cms_signature_invalid' };
    }

    // 2. Хеші DG1/DG2, ПІДПИСАНІ державою, проти хешів клієнта.
    let lds;
    try {
      lds = parseLDSSecurityObject(await fs.promises.readFile(contentPath));
    } catch (e) {
      return { status: 'failed', reason: 'lds_parse_failed' };
    }

    const clientDG1 = dgHashes?.dg1?.[lds.algorithm];
    const clientDG2 = dgHashes?.dg2?.[lds.algorithm];
    if (!clientDG1 || !clientDG2) {
      return { status: 'failed', reason: `client_hash_missing_${lds.algorithm}` };
    }
    if (String(clientDG1).toLowerCase() !== lds.dgHashes[1] ||
        String(clientDG2).toLowerCase() !== lds.dgHashes[2]) {
      return { status: 'failed', reason: 'dg_hash_mismatch', algorithm: lds.algorithm };
    }

    // 3. Ланцюжок довіри: DSC → запінені CSCA України.
    if (!fs.existsSync(MASTERLIST)) {
      return { status: 'unavailable', reason: 'masterlist_missing', algorithm: lds.algorithm };
    }
    try {
      const args = ['verify', '-CAfile', MASTERLIST];
      if (NO_CHECK_TIME) args.push('-no_check_time');
      args.push('-untrusted', certsPath, signerPath);
      await openssl(args);
    } catch {
      return { status: 'failed', reason: 'csca_chain_failed', algorithm: lds.algorithm };
    }

    // 4. Країна: емітент DSC мусить бути українська CSCA (C=UA).
    let issuer = '';
    try {
      issuer = (await openssl(['x509', '-in', signerPath, '-noout', '-issuer'])).toString();
    } catch { /* ланцюжок уже перевірено */ }
    if (REQUIRE_UA && issuer && !/\bC\s*=\s*UA\b/.test(issuer)) {
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
  } catch (e) {
    return { status: 'failed', reason: 'exception: ' + e.message };
  } finally {
    if (tmp) { try { await fs.promises.rm(tmp, { recursive: true, force: true }); } catch { /* noop */ } }
    release();
  }
}

module.exports = { verifySOD, parseLDSSecurityObject, stripIcaoWrapper };
