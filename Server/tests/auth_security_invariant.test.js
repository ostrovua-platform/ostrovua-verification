'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function read(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

test('distributed limiter serializes updates and is unavailable to PUBLIC', () => {
  const migration = read('migrations/20260725_auth_security.sql');
  const limiterStart = migration.indexOf('CREATE OR REPLACE FUNCTION public.auth_rate_limit_consume');
  const limiterEnd = migration.indexOf('CREATE TABLE IF NOT EXISTS public.auth_sessions', limiterStart);
  const limiter = migration.slice(limiterStart, limiterEnd);

  assert.match(limiter, /FOR UPDATE/);
  assert.match(limiter, /blocked_until/);
  assert.match(migration, /REVOKE ALL ON FUNCTION public\.auth_rate_limit_consume/);
});

test('password reset and change revoke all active sessions atomically', () => {
  const migration = read('migrations/20260725_auth_security.sql');
  const changeStart = migration.indexOf('CREATE OR REPLACE FUNCTION public.auth_change_password');
  const resetStart = migration.indexOf('CREATE OR REPLACE FUNCTION public.secure_password_reset');
  const deletionStart = migration.indexOf('CREATE TABLE IF NOT EXISTS public.uploaded_files');
  const change = migration.slice(changeStart, resetStart);
  const reset = migration.slice(resetStart, deletionStart);

  assert.match(change, /password_hash = p_current_password_hash/);
  assert.match(change, /UPDATE public\.auth_sessions[\s\S]+revoked_at/);
  assert.match(reset, /FOR UPDATE/);
  assert.match(reset, /attempts = attempts \+ 1/);
  assert.match(reset, /UPDATE public\.auth_sessions[\s\S]+revoked_at/);
});

test('account deletion is transactional and preserves a non-identifying receipt', () => {
  const migration = read('migrations/20260725_auth_security.sql');
  const start = migration.indexOf('CREATE OR REPLACE FUNCTION public.delete_account_complete');
  const end = migration.indexOf('CREATE OR REPLACE FUNCTION public.account_deletion_file_removed', start);
  const deletion = migration.slice(start, end);

  assert.match(deletion, /FOR UPDATE/);
  assert.match(deletion, /DELETE FROM public\.contributors/);
  assert.match(deletion, /account_deletion_receipts/);
  assert.match(deletion, /account_deletion_files/);
  assert.match(
    deletion,
    /INSERT INTO public\.account_deletion_receipts\(id\)\s+VALUES \(p_receipt_id\)/
  );
});

test('revoked bearer sessions gate Hasura and security flags stay fail-closed', () => {
  const server = read('server.js');
  const nginx = read('nginx/nginx.conf');

  assert.match(server, /AUTH_SESSION_ENFORCEMENT_ENABLED\s*=\s*process\.env\.AUTH_SESSION_ENFORCEMENT_ENABLED === '1'/);
  assert.match(server, /authSecurityStore\.isSessionActive/);
  assert.match(server, /app\.get\('\/auth\/introspect'/);
  assert.match(nginx, /auth_request\s+\/_auth_session/);
  assert.match(nginx, /proxy_pass\s+http:\/\/auth\/auth\/introspect/);
});
