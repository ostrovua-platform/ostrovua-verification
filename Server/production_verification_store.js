'use strict';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;
const POLICY = /^[a-zA-Z0-9_.-]{8,100}$/;
const RATE_KEY = /^(?:acct:[0-9a-fA-F-]{36}|dev:[A-Za-z0-9+/=_-]{1,64})$/;
const APP_ATTEST_KEY = /^[A-Za-z0-9+/]{43}=$/;
const DOCUMENT_CHALLENGE = /^[A-Za-z0-9_-]{22}$/;

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function quoted(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

function text(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new Error(`${label}_invalid`);
  }
  return `${quoted(value)}::text`;
}

function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) {
    throw new Error(`${label}_invalid`);
  }
  return `${quoted(value)}::uuid`;
}

function nullableHex(value, current) {
  if (value === null) return 'NULL::text';
  if (typeof value !== 'string' || !HEX64.test(value) || value === current) {
    throw new Error('legacy_document_token_invalid');
  }
  return `${quoted(value)}::text`;
}

function integer(value, minimum, maximum, label, cast = 'integer') {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label}_invalid`);
  }
  return `${value}::${cast}`;
}

function numeric(value, minimum, maximum, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) ||
      value < minimum || value > maximum) {
    throw new Error(`${label}_invalid`);
  }
  return `${value.toFixed(6)}::numeric`;
}

function scalarOutcome(rows) {
  if (!Array.isArray(rows) || rows.length !== 1 ||
      !Array.isArray(rows[0]) || rows[0].length !== 1 ||
      typeof rows[0][0] !== 'string') {
    throw new Error('verification_database_response_invalid');
  }
  return rows[0][0];
}

function parseRateLimit(rows) {
  if (!Array.isArray(rows) || rows.length !== 1 ||
      !Array.isArray(rows[0]) || rows[0].length !== 3 ||
      !['t', 'f', true, false].includes(rows[0][0]) ||
      !Number.isInteger(Number(rows[0][2]))) {
    throw new Error('verification_rate_limit_response_invalid');
  }
  const until = rows[0][1] || null;
  if (until !== null && Number.isNaN(new Date(until).getTime())) {
    throw new Error('verification_rate_limit_response_invalid');
  }
  return {
    locked: rows[0][0] === 't' || rows[0][0] === true,
    until,
    tier: Number(rows[0][2]),
  };
}

function createProductionVerificationStore(runSql) {
  if (typeof runSql !== 'function') throw new Error('run_sql_required');

  return Object.freeze({
    async rateLimit(functionName, key) {
      if (!['rl_touch', 'rl_check'].includes(functionName) ||
          typeof key !== 'string' || !RATE_KEY.test(key)) {
        throw new Error('verification_rate_limit_key_invalid');
      }
      const rows = await runSql(
        `SELECT is_locked, until, cur_tier FROM ${functionName}(${quoted(key)}::text)`
      );
      return parseRateLimit(rows);
    },

    async resetRateLimit(key) {
      if (typeof key !== 'string' || !RATE_KEY.test(key)) {
        throw new Error('verification_rate_limit_key_invalid');
      }
      await runSql(`SELECT rl_reset(${quoted(key)}::text)`);
    },

    async activateSelfHostedV7(input) {
      const keys = [
        'documentToken', 'legacyDocumentToken', 'contributorId', 'requestId',
        'policyVersion', 'modelSetHash', 'receiptDigest', 'receiptSignature',
        'serviceTimestamp', 'protocolVersion', 'documentAssurance',
      ];
      if (!exactKeys(input, keys) ||
          input.protocolVersion !== 7 ||
          input.documentAssurance !== 'active_authentication') {
        throw new Error('verification_activation_input_invalid');
      }
      const documentToken = text(input.documentToken, HEX64, 'document_token');
      const sql = [
        'SELECT activate_self_hosted_verified_id_v7_rotating(',
        documentToken,
        nullableHex(input.legacyDocumentToken, input.documentToken),
        uuid(input.contributorId, 'contributor_id'),
        uuid(input.requestId, 'request_id'),
        text(input.policyVersion, POLICY, 'policy_version'),
        text(input.modelSetHash, HEX64, 'model_set_hash'),
        text(input.receiptDigest, HEX64, 'receipt_digest'),
        text(input.receiptSignature, HEX64, 'receipt_signature'),
        integer(input.serviceTimestamp, 1, 9_999_999_999, 'service_timestamp', 'bigint'),
        '7::integer',
        `${quoted('active_authentication')}::text`,
      ];
      return scalarOutcome(await runSql(`${sql[0]}${sql.slice(1).join(', ')})`));
    },

    async activateSelfHostedCAV7(input) {
      const keys = [
        'documentToken', 'legacyDocumentToken', 'contributorId', 'requestId',
        'policyVersion', 'modelSetHash', 'receiptDigest', 'receiptSignature',
        'serviceTimestamp', 'protocolVersion', 'documentAssurance',
        'attestKeyId', 'documentChallengeId', 'dg14Hash',
      ];
      if (!exactKeys(input, keys) ||
          input.protocolVersion !== 7 ||
          input.documentAssurance !== 'chip_authentication_server') {
        throw new Error('verification_ca_activation_input_invalid');
      }
      const documentToken = text(input.documentToken, HEX64, 'document_token');
      const sql = [
        'SELECT activate_self_hosted_verified_id_v7_ca_rotating(',
        documentToken,
        nullableHex(input.legacyDocumentToken, input.documentToken),
        uuid(input.contributorId, 'contributor_id'),
        uuid(input.requestId, 'request_id'),
        text(input.policyVersion, POLICY, 'policy_version'),
        text(input.modelSetHash, HEX64, 'model_set_hash'),
        text(input.receiptDigest, HEX64, 'receipt_digest'),
        text(input.receiptSignature, HEX64, 'receipt_signature'),
        integer(input.serviceTimestamp, 1, 9_999_999_999, 'service_timestamp', 'bigint'),
        '7::integer',
        `${quoted('chip_authentication_server')}::text`,
        text(input.attestKeyId, APP_ATTEST_KEY, 'attest_key_id'),
        text(input.documentChallengeId, DOCUMENT_CHALLENGE, 'document_challenge_id'),
        text(input.dg14Hash, HEX64, 'dg14_hash'),
      ];
      return scalarOutcome(await runSql(`${sql[0]}${sql.slice(1).join(', ')})`));
    },

    async submitReviewV7(input) {
      const keys = [
        'documentToken', 'legacyDocumentToken', 'contributorId', 'faceModel',
        'faceModelVersion', 'faceScore', 'faceThreshold', 'faceSampleCount',
        'faceContinuityScore', 'livenessFrameCount', 'livenessDurationMs',
        'protocolVersion', 'documentAssurance',
      ];
      if (!exactKeys(input, keys) ||
          input.protocolVersion !== 7 ||
          input.faceModel !== 'coreml' ||
          input.faceModelVersion !== 'facenet-vggface2-coreml-04a4db780288799e' ||
          input.faceThreshold !== 0.5 ||
          !['passive_only', 'chip_authentication_attested']
            .includes(input.documentAssurance)) {
        throw new Error('verification_review_input_invalid');
      }
      const documentToken = text(input.documentToken, HEX64, 'document_token');
      const sql = [
        'SELECT submit_verification_review_v7_rotating(',
        documentToken,
        nullableHex(input.legacyDocumentToken, input.documentToken),
        uuid(input.contributorId, 'contributor_id'),
        `${quoted('coreml')}::text`,
        `${quoted('facenet-vggface2-coreml-04a4db780288799e')}::text`,
        numeric(input.faceScore, -1, 1, 'face_score'),
        numeric(input.faceThreshold, 0.5, 0.5, 'face_threshold'),
        integer(input.faceSampleCount, 3, 5, 'face_sample_count'),
        numeric(input.faceContinuityScore, 0.4, 1, 'face_continuity_score'),
        integer(input.livenessFrameCount, 8, 3000, 'liveness_frame_count'),
        integer(input.livenessDurationMs, 500, 30000, 'liveness_duration_ms'),
        '7::integer',
        `${quoted(input.documentAssurance)}::text`,
      ];
      return scalarOutcome(await runSql(`${sql[0]}${sql.slice(1).join(', ')})`));
    },
  });
}

module.exports = { createProductionVerificationStore };
