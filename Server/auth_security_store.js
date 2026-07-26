'use strict';

const crypto = require('crypto');

function sqlLiteral(value) {
  if (value == null) return 'NULL';
  return `'${String(value).replace(/'/g, "''")}'`;
}

function uuid(value, label = 'uuid') {
  const normalized = String(value || '').toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(normalized)) {
    throw new Error(`${label}_invalid`);
  }
  return normalized;
}

function integer(value, minimum, maximum, label) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label}_invalid`);
  }
  return value;
}

function parseBoolean(value) {
  return value === true || value === 't' || value === 'true';
}

function createAuthSecurityStore(hasuraSQL, { rateLimitPepper, metadataPepper }) {
  if (typeof hasuraSQL !== 'function') throw new Error('hasura_sql_required');
  if (!rateLimitPepper || Buffer.byteLength(rateLimitPepper, 'utf8') < 32) {
    throw new Error('auth_rate_limit_pepper_invalid');
  }
  if (!metadataPepper || Buffer.byteLength(metadataPepper, 'utf8') < 32) {
    throw new Error('auth_session_metadata_pepper_invalid');
  }

  const hmac = (pepper, value) => crypto
    .createHmac('sha256', pepper)
    .update(String(value || ''), 'utf8')
    .digest('hex');

  return {
    identityHash(value) {
      return hmac(rateLimitPepper, value);
    },

    metadataHash(value) {
      if (!value) return null;
      return hmac(metadataPepper, value);
    },

    async consumeRateLimit({ bucket, identity, limit, windowSeconds, blockSeconds }) {
      if (!/^[a-z0-9:_-]{1,64}$/.test(bucket || '')) {
        throw new Error('auth_rate_limit_bucket_invalid');
      }
      const keyHash = this.identityHash(identity);
      integer(limit, 1, 10000, 'auth_rate_limit_limit');
      integer(windowSeconds, 1, 86400, 'auth_rate_limit_window');
      integer(blockSeconds, 1, 604800, 'auth_rate_limit_block');

      const rows = await hasuraSQL(
        `SELECT allowed, retry_after_seconds
           FROM auth_rate_limit_consume(
             ${sqlLiteral(bucket)},
             ${sqlLiteral(keyHash)},
             ${limit},
             ${windowSeconds},
             ${blockSeconds}
           )`
      );
      if (!Array.isArray(rows) || rows.length !== 1 || rows[0].length < 2) {
        throw new Error('auth_rate_limit_response_invalid');
      }
      return {
        allowed: parseBoolean(rows[0][0]),
        retryAfterSeconds: Math.max(0, Number.parseInt(rows[0][1], 10) || 0),
      };
    },

    async createSession({ sessionId, contributorId, expiresAt, ip, userAgent }) {
      const sid = uuid(sessionId, 'auth_session_id');
      const subject = uuid(contributorId, 'auth_session_contributor_id');
      const expiry = new Date(expiresAt);
      if (!Number.isFinite(expiry.getTime()) || expiry <= new Date()) {
        throw new Error('auth_session_expiry_invalid');
      }
      const rows = await hasuraSQL(
        `SELECT auth_session_create(
          ${sqlLiteral(sid)}::uuid,
          ${sqlLiteral(subject)}::uuid,
          ${sqlLiteral(expiry.toISOString())}::timestamptz,
          ${sqlLiteral(this.metadataHash(ip))},
          ${sqlLiteral(this.metadataHash(userAgent))}
        )`
      );
      if (!Array.isArray(rows) || rows.length !== 1 || !parseBoolean(rows[0][0])) {
        throw new Error('auth_session_create_failed');
      }
    },

    async isSessionActive({ sessionId, contributorId }) {
      const sid = uuid(sessionId, 'auth_session_id');
      const subject = uuid(contributorId, 'auth_session_contributor_id');
      const rows = await hasuraSQL(
        `SELECT auth_session_is_active(
          ${sqlLiteral(sid)}::uuid,
          ${sqlLiteral(subject)}::uuid
        )`
      );
      if (!Array.isArray(rows) || rows.length !== 1) {
        throw new Error('auth_session_check_failed');
      }
      return parseBoolean(rows[0][0]);
    },

    async revokeSession({ sessionId, contributorId }) {
      const sid = uuid(sessionId, 'auth_session_id');
      const subject = uuid(contributorId, 'auth_session_contributor_id');
      const rows = await hasuraSQL(
        `SELECT auth_session_revoke(
          ${sqlLiteral(sid)}::uuid,
          ${sqlLiteral(subject)}::uuid
        )`
      );
      return Array.isArray(rows) && rows.length === 1 && parseBoolean(rows[0][0]);
    },

    async revokeAllSessions(contributorId) {
      const subject = uuid(contributorId, 'auth_session_contributor_id');
      const rows = await hasuraSQL(
        `SELECT auth_sessions_revoke_all(${sqlLiteral(subject)}::uuid)`
      );
      if (!Array.isArray(rows) || rows.length !== 1) {
        throw new Error('auth_session_revoke_all_failed');
      }
      return Number.parseInt(rows[0][0], 10) || 0;
    },

    async changePassword({ contributorId, currentPasswordHash, passwordHash }) {
      const subject = uuid(contributorId, 'auth_session_contributor_id');
      const legacyHash = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;
      const versionedHash = /^ovua\$bcrypt-sha512\$v1\$\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;
      if (!legacyHash.test(currentPasswordHash || '') &&
          !versionedHash.test(currentPasswordHash || '')) {
        throw new Error('current_password_hash_format_invalid');
      }
      if (!/^ovua\$bcrypt-sha512\$v1\$\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(passwordHash || '')) {
        throw new Error('password_hash_format_invalid');
      }
      const rows = await hasuraSQL(
        `SELECT auth_change_password(
          ${sqlLiteral(subject)}::uuid,
          ${sqlLiteral(currentPasswordHash)},
          ${sqlLiteral(passwordHash)}
        )`
      );
      if (!Array.isArray(rows) || rows.length !== 1 || !parseBoolean(rows[0][0])) {
        throw new Error('password_change_failed');
      }
    },

    async resetPassword({ contributorId, candidateHash, passwordHash }) {
      const subject = uuid(contributorId, 'password_reset_contributor_id');
      if (!/^[0-9a-f]{64}$/.test(candidateHash || '')) {
        throw new Error('password_reset_candidate_invalid');
      }
      if (!/^ovua\$bcrypt-sha512\$v1\$\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(passwordHash || '')) {
        throw new Error('password_hash_format_invalid');
      }
      const rows = await hasuraSQL(
        `SELECT secure_password_reset(
          ${sqlLiteral(subject)}::uuid,
          ${sqlLiteral(candidateHash)},
          ${sqlLiteral(passwordHash)}
        )`
      );
      if (!Array.isArray(rows) || rows.length !== 1 || !rows[0][0]) {
        throw new Error('password_reset_response_invalid');
      }
      return String(rows[0][0]);
    },

    async recordDocumentCAReceipt({
      sessionId,
      contributorId,
      attestKeyId,
      documentChallengeId,
      dg14Hash,
      protocolOID,
      keyId,
      expiresAt,
    }) {
      const session = uuid(sessionId, 'document_ca_session_id');
      const subject = uuid(contributorId, 'document_ca_contributor_id');
      if (!/^[A-Za-z0-9+/]{43}=$/.test(attestKeyId || '') ||
          !/^[A-Za-z0-9_-]{22}$/.test(documentChallengeId || '') ||
          !/^[0-9a-f]{64}$/.test(dg14Hash || '') ||
          ![
            '0.4.0.127.0.7.2.2.3.2.2',
            '0.4.0.127.0.7.2.2.3.2.3',
            '0.4.0.127.0.7.2.2.3.2.4',
          ].includes(protocolOID) ||
          (keyId !== null &&
            (!Number.isInteger(keyId) || keyId < 0 || keyId > 4294967294))) {
        throw new Error('document_ca_receipt_invalid');
      }
      const expiry = new Date(expiresAt);
      if (!Number.isFinite(expiry.getTime()) ||
          expiry <= new Date() ||
          expiry > new Date(Date.now() + 5 * 60 * 1000)) {
        throw new Error('document_ca_receipt_expiry_invalid');
      }
      const rows = await hasuraSQL(
        `SELECT document_ca_record_receipt(
          ${sqlLiteral(session)}::uuid,
          ${sqlLiteral(subject)}::uuid,
          ${sqlLiteral(attestKeyId)}::text,
          ${sqlLiteral(documentChallengeId)}::text,
          ${sqlLiteral(dg14Hash)}::text,
          ${sqlLiteral(protocolOID)}::text,
          ${keyId === null ? 'NULL::bigint' : `${keyId}::bigint`},
          ${sqlLiteral(expiry.toISOString())}::timestamptz
        )`
      );
      return Array.isArray(rows) && rows.length === 1 && parseBoolean(rows[0][0]);
    },

    async hasDocumentCAReceipt({
      contributorId,
      attestKeyId,
      documentChallengeId,
      dg14Hash,
    }) {
      const subject = uuid(contributorId, 'document_ca_contributor_id');
      if (!/^[A-Za-z0-9+/]{43}=$/.test(attestKeyId || '') ||
          !/^[A-Za-z0-9_-]{22}$/.test(documentChallengeId || '') ||
          !/^[0-9a-f]{64}$/.test(dg14Hash || '')) {
        throw new Error('document_ca_receipt_lookup_invalid');
      }
      const rows = await hasuraSQL(
        `SELECT document_ca_receipt_available(
          ${sqlLiteral(subject)}::uuid,
          ${sqlLiteral(attestKeyId)}::text,
          ${sqlLiteral(documentChallengeId)}::text,
          ${sqlLiteral(dg14Hash)}::text
        )`
      );
      if (!Array.isArray(rows) || rows.length !== 1) {
        throw new Error('document_ca_receipt_lookup_failed');
      }
      return parseBoolean(rows[0][0]);
    },

    async registerUpload({ filename, contributorId }) {
      if (!/^[0-9a-f]{32}\.(?:jpg|png|gif|webp|heic|avif|mp4|mov|m4a|webm|pdf)$/.test(filename || '')) {
        throw new Error('upload_filename_invalid');
      }
      const subject = uuid(contributorId, 'upload_contributor_id');
      const rows = await hasuraSQL(
        `SELECT uploaded_file_register(
          ${sqlLiteral(filename)},
          ${sqlLiteral(subject)}::uuid
        )`
      );
      if (!Array.isArray(rows) || rows.length !== 1 || !parseBoolean(rows[0][0])) {
        throw new Error('upload_registration_failed');
      }
    },

    async deleteAccount({ contributorId, receiptId }) {
      const subject = uuid(contributorId, 'account_deletion_contributor_id');
      const receipt = uuid(receiptId, 'account_deletion_receipt_id');
      const rows = await hasuraSQL(
        `SELECT delete_account_complete(
          ${sqlLiteral(subject)}::uuid,
          ${sqlLiteral(receipt)}::uuid
        )::text`
      );
      if (!Array.isArray(rows) || rows.length !== 1 || !rows[0][0]) {
        throw new Error('account_deletion_response_invalid');
      }
      const result = JSON.parse(rows[0][0]);
      if (result.status !== 'deleted' || !Array.isArray(result.files)) {
        throw new Error('account_deletion_failed');
      }
      return result;
    },

    async markDeletionFileRemoved({ receiptId, filename }) {
      const receipt = uuid(receiptId, 'account_deletion_receipt_id');
      if (!/^[0-9a-f]{32}\.(?:jpg|png|gif|webp|heic|avif|mp4|mov|m4a|webm|pdf)$/.test(filename || '')) {
        throw new Error('upload_filename_invalid');
      }
      const rows = await hasuraSQL(
        `SELECT account_deletion_file_removed(
          ${sqlLiteral(receipt)}::uuid,
          ${sqlLiteral(filename)}
        )`
      );
      return Array.isArray(rows) && rows.length === 1 && parseBoolean(rows[0][0]);
    },

    async pendingDeletionFiles(limit = 100) {
      integer(limit, 1, 1000, 'account_deletion_batch_limit');
      const rows = await hasuraSQL(
        `SELECT receipt_id::text, filename
           FROM account_deletion_pending_files(${limit})`
      );
      if (!Array.isArray(rows)) throw new Error('account_deletion_pending_response_invalid');
      return rows.map((row) => ({
        receiptId: uuid(row[0], 'account_deletion_receipt_id'),
        filename: String(row[1] || ''),
      }));
    },
  };
}

module.exports = {
  createAuthSecurityStore,
  sqlLiteral,
};
