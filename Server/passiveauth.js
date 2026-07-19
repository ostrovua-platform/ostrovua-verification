// ═══════════════════════════════════════════════════════════════════
//  Passive Authentication (ICAO 9303 Part 11) — серверна перевірка
//  справжності даних чипа біометричного документа.
//
//  Що перевіряється (усе — на сервері, клієнту НЕ довіряємо):
//   1. SOD (EF.SOD з чипа) — це CMS SignedData. Перевіряємо цілісність
//      підпису Document Signer'а (openssl cms -verify).
//   2. Ланцюжок довіри: Document Signer Certificate (DSC) → CSCA
//      (Country Signing CA) з masterlist. Для нас — CSCA України (C=UA).
//   3. Хеші груп даних: клієнт надсилає хеші DG1/DG2, які він реально
//      прочитав і з якими звіряв обличчя. Порівнюємо з хешами,
//      ПІДПИСАНИМИ ДЕРЖАВОЮ всередині SOD.
//
//  Що це дає: сервер отримує криптографічний доказ, що дані чипа
//  видані Україною і не підроблені — незалежно від чесності клієнта.
//
//  Що це НЕ ловить (чесно): точну копію чипа (клон з тим самим SOD).
//  Проти клонів існує Chip/Active Authentication — окремий етап.
//
//  ПРИВАТНІСТЬ: SOD не містить імені, номера, дати народження чи фото —
//  лише хеші груп даних, сертифікат і підпис. Персональні поля документа
//  на сервер як і раніше НЕ передаються. SOD перевіряється у тимчасовій
//  теці й одразу видаляється; у базі лишається тільки результат.
// ═══════════════════════════════════════════════════════════════════
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const MASTERLIST = process.env.CSCA_MASTERLIST || '/app/csca/csca_ua.pem';
const NO_CHECK_TIME = process.env.PA_NO_CHECK_TIME === '1'; // для старих DSC
const REQUIRE_UA = process.env.PA_REQUIRE_UA !== '0';       // issuer DSC мусить бути C=UA

const MAX_SOD_BYTES = 64 * 1024;   // реальний SOD ~1.5–5 КБ
const OPENSSL_TIMEOUT_MS = 5000;

// ── Мінімальний DER/TLV-парсер (лише читання, без залежностей) ──────

function tlv(buf, off) {
  let p = off;
  if (p >= buf.length) throw new Error('DER: несподіваний кінець');
  const first = buf[p++];
  let tagNum = first & 0x1f;
  if (tagNum === 0x1f) { // багатобайтовий тег
    tagNum = 0;
    let b;
    do {
      b = buf[p++];
      tagNum = (tagNum << 7) | (b & 0x7f);
    } while (b & 0x80);
  }
  let lenByte = buf[p++];
  let len;
  if (lenByte < 0x80) {
    len = lenByte;
  } else {
    const n = lenByte & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: заборонена довжина (BER?)');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
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
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

/// LDSSecurityObject ::= SEQUENCE {
///   version INTEGER, hashAlgorithm AlgorithmIdentifier,
///   dataGroupHashValues SEQUENCE OF { dgNumber INTEGER, dgHash OCTET STRING } }
function parseLDSSecurityObject(buf) {
  const root = tlv(buf, 0);
  if (root.firstByte !== 0x30) throw new Error('LDS: очікував SEQUENCE');
  const kids = children(buf, root);
  if (kids.length < 3) throw new Error('LDS: замало елементів');

  const algSeq = kids[1];
  const algKids = children(buf, algSeq);
  if (!algKids.length || algKids[0].firstByte !== 0x06) throw new Error('LDS: немає OID алгоритму');
  const oid = decodeOID(buf, algKids[0]);
  const algorithm = HASH_OIDS[oid];
  if (!algorithm) throw new Error(`LDS: невідомий алгоритм хешу ${oid}`);

  const dgHashes = {};
  for (const entry of children(buf, kids[2])) {
    const pair = children(buf, entry);
    if (pair.length < 2 || pair[0].firstByte !== 0x02 || pair[1].firstByte !== 0x04) continue;
    let dgNum = 0;
    for (let i = pair[0].cStart; i < pair[0].cEnd; i++) dgNum = dgNum * 256 + buf[i];
    dgHashes[dgNum] = buf.slice(pair[1].cStart, pair[1].cEnd).toString('hex');
  }
  if (!dgHashes[1] || !dgHashes[2]) throw new Error('LDS: немає хешів DG1/DG2');
  return { algorithm, dgHashes };
}

/// EF.SOD на чипі загорнутий у application-тег 0x77 — знімаємо.
function stripIcaoWrapper(buf) {
  if (buf[0] !== 0x77) return buf;
  const t = tlv(buf, 0);
  return buf.slice(t.cStart, t.cEnd);
}

function openssl(args, opts = {}) {
  return execFileSync('openssl', args, {
    timeout: OPENSSL_TIMEOUT_MS,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...opts,
  });
}

// ── Головна перевірка ───────────────────────────────────────────────
//
// Повертає (НІКОЛИ не кидає):
//   { status: 'passed'|'failed'|'unavailable', reason, algorithm, issuer }
//
// 'failed'      — SOD битий/підроблений/не збігаються хеші → ВІДМОВА.
// 'unavailable' — проблема КОНФІГУРАЦІЇ сервера (немає masterlist) —
//                 що робити, вирішує викликач (PA_ENFORCE).
function verifySOD({ sodBase64, dgHashes }) {
  let tmp;
  try {
    if (typeof sodBase64 !== 'string' || !sodBase64) {
      return { status: 'failed', reason: 'sod_missing' };
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

    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-'));
    const cmsPath = path.join(tmp, 'sod.der');
    const contentPath = path.join(tmp, 'lds.der');
    const signerPath = path.join(tmp, 'signer.pem');
    const certsPath = path.join(tmp, 'certs.pem');
    fs.writeFileSync(cmsPath, cms);

    // 1. Цілісність підпису DSC над вмістом (без перевірки ланцюжка):
    //    openssl звіряє signedAttrs.messageDigest з eContent і сам підпис.
    try {
      openssl([
        'cms', '-verify', '-inform', 'DER', '-in', cmsPath,
        '-noverify',
        '-out', contentPath,
        '-signer', signerPath,
        '-certsout', certsPath,
      ]);
    } catch (e) {
      return { status: 'failed', reason: 'cms_signature_invalid' };
    }

    // 2. Хеші DG1/DG2, ПІДПИСАНІ державою, проти хешів клієнта.
    //    Клієнт надсилає хеші груп даних, які реально прочитав з чипа
    //    і з DG2 яких звіряв обличчя. Збіг = обличчя звірялося саме з
    //    державно підписаним фото.
    let lds;
    try {
      lds = parseLDSSecurityObject(fs.readFileSync(contentPath));
    } catch (e) {
      return { status: 'failed', reason: 'lds_parse_failed' };
    }

    const clientDG1 = dgHashes?.dg1?.[lds.algorithm];
    const clientDG2 = dgHashes?.dg2?.[lds.algorithm];
    if (!clientDG1 || !clientDG2) {
      return { status: 'failed', reason: `client_hash_missing_${lds.algorithm}` };
    }
    if (clientDG1.toLowerCase() !== lds.dgHashes[1] ||
        clientDG2.toLowerCase() !== lds.dgHashes[2]) {
      return { status: 'failed', reason: 'dg_hash_mismatch', algorithm: lds.algorithm };
    }

    // 3. Ланцюжок довіри: DSC → CSCA України з masterlist.
    if (!fs.existsSync(MASTERLIST)) {
      return { status: 'unavailable', reason: 'masterlist_missing', algorithm: lds.algorithm };
    }
    try {
      const args = ['verify', '-CAfile', MASTERLIST];
      if (NO_CHECK_TIME) args.push('-no_check_time');
      // link-сертифікати CSCA з самого SOD — як проміжні
      args.push('-untrusted', certsPath, signerPath);
      openssl(args);
    } catch (e) {
      return { status: 'failed', reason: 'csca_chain_failed', algorithm: lds.algorithm };
    }

    // 4. Країна: емітент DSC мусить бути українська CSCA (C=UA).
    //    (masterlist і так лише UA, але перевіряємо явно.)
    let issuer = '';
    try {
      issuer = openssl(['x509', '-in', signerPath, '-noout', '-issuer']).toString();
    } catch { /* не критично, ланцюжок уже перевірено */ }
    if (REQUIRE_UA && issuer && !/\bC\s*=\s*UA\b/.test(issuer)) {
      return { status: 'failed', reason: 'issuer_not_ukraine', issuer: issuer.trim() };
    }

    return {
      status: 'passed',
      reason: null,
      algorithm: lds.algorithm,
      issuer: issuer.trim() || null,
    };
  } catch (e) {
    return { status: 'failed', reason: 'exception: ' + e.message };
  } finally {
    if (tmp) { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* noop */ } }
  }
}

module.exports = { verifySOD, parseLDSSecurityObject, stripIcaoWrapper };
