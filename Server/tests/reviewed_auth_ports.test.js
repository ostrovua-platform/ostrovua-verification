'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const ownerId = '00000000-0000-4000-8000-000000000001';
const otherId = '00000000-0000-4000-8000-000000000002';

// Load the real handlers without starting the server or contacting providers.
function oauthHarness(accounts = []) {
  const calls = [];
  const callbacks = {};
  const context = {
    withTheme: async account => account,
    hasuraAdmin: async (query, values) => {
      calls.push({ query, values });
      if (query.trim().startsWith('query')) {
        const account = accounts.find(row => values.pid
          ? row.oauth_provider_id === values.pid && row.oauth_provider === values.prov
          : row.email === values.email);
        const fields = query.match(/\{ id ([^}]+)\}/)[1].trim().split(/\s+/);
        return { contributors: account ? [{ id: account.id,
          ...Object.fromEntries(fields.map(field => [field, account[field]])) }] : [] };
      }
      if (values.obj) return { insert_contributors_one: { id: otherId, ...values.obj } };
      return { update_contributors: { affected_rows: 1 }, update_contributors_by_pk: { id: values.id } };
    },
    GOOGLE_CLIENT_ID: 'synthetic-google', GOOGLE_CLIENT_SECRET: '',
    GITHUB_CLIENT_ID: 'synthetic-github', GITHUB_CLIENT_SECRET: '', AUTH_BASE_URL: 'https://auth.example.test',
    GoogleStrategy: class { constructor(_options, callback) { this.provider = 'google'; this.callback = callback; } },
    GitHubStrategy: class { constructor(_options, callback) { this.provider = 'github'; this.callback = callback; } },
    passport: { use(strategy) { callbacks[strategy.provider] = strategy.callback; }, authenticate: () => () => {} },
    app: { get() {} }, startOAuth() {}, verifyOAuthState() {},
  };
  const start = source.indexOf('async function findOrCreateContributor(');
  const end = source.indexOf('// ── JWT HELPER', start);
  assert.ok(start >= 0 && end > start);
  vm.runInNewContext(source.slice(start, end), context);
  const providersStart = source.indexOf('// ── GOOGLE OAUTH');
  const providersEnd = source.indexOf('// ── TELEGRAM WIDGET PAGE', providersStart);
  assert.ok(providersStart > 0 && providersEnd > providersStart);
  vm.runInNewContext(source.slice(providersStart, providersEnd), context);
  return { calls, find: context.findOrCreateContributor,
    login: (provider, profile) => new Promise((resolve, reject) => {
      callbacks[provider]('', '', profile, (error, account) => error ? reject(error) : resolve(account));
    }) };
}

function victim(provider = null, providerId = null) {
  return { id: ownerId, email: 'victim@example.test', name: 'Existing user',
    oauth_provider: provider, oauth_provider_id: providerId, verified: true };
}

test('GitHub unverified email cannot authenticate or link another account', async () => {
  const harness = oauthHarness([victim()]);
  const account = await harness.login('github', { id: 'attacker', username: 'new-user',
    emails: [{ value: 'victim@example.test', primary: true, verified: false }] });
  assert.notEqual(account.id, ownerId);
  assert.equal(account.email, null, 'unverified email is not persisted on the new account');
  assert.ok(harness.calls.every(call => !call.values.email && !call.values.id));
});

test('Google requires the literal provider email_verified flag before email lookup', async () => {
  for (const email_verified of [undefined, false, 'true']) {
    const harness = oauthHarness([victim()]);
    const account = await harness.login('google', { id: 'attacker',
      emails: [{ value: 'victim@example.test' }], _json: { email_verified } });
    assert.notEqual(account.id, ownerId);
    assert.equal(account.email, null);
    assert.ok(harness.calls.every(call => !call.values.email && !call.values.id));
  }
});

test('identity resolver defaults to unverified even when passed an email directly', async () => {
  const harness = oauthHarness([victim()]);
  const account = await harness.find({ email: 'victim@example.test', provider: 'github', provider_id: 'attacker' });
  assert.notEqual(account.id, ownerId);
  assert.equal(account.email, null);
});

test('verified email cannot silently replace a different linked provider', async () => {
  for (const [provider, providerId] of [['google', 'original-google'], ['github', 'original-github']]) {
    const harness = oauthHarness([victim(provider, providerId)]);
    await assert.rejects(harness.login('github', { id: 'new-github',
      emails: [{ value: 'victim@example.test', primary: true, verified: true }] }), /інший спосіб входу/);
    assert.ok(harness.calls.every(call => call.query.trim().startsWith('query')));
  }
});

test('existing provider identity keeps working without a verified email', async () => {
  const harness = oauthHarness([victim('github', 'existing-github')]);
  const account = await harness.login('github', { id: 'existing-github', emails: [] });
  assert.equal(account.id, ownerId);
  assert.equal(harness.calls.length, 1);
});

test('verified Google and GitHub email can link an account with no provider', async () => {
  for (const provider of ['google', 'github']) {
    const harness = oauthHarness([victim()]);
    const profile = { id: 'new-provider', emails: [{ value: 'victim@example.test', verified: true }],
      _json: { email_verified: true } };
    const account = await harness.login(provider, profile);
    assert.equal(account.id, ownerId);
    const mutation = harness.calls.find(call => !call.query.trim().startsWith('query'));
    assert.equal(mutation.values.id, ownerId);
    assert.equal(mutation.values.prov, provider);
    assert.equal(mutation.values.pid, 'new-provider');
  }
});

function deviceTokenHarness(authenticatedId = ownerId) {
  let handler;
  const rows = [{ token: 'own-token', contributor_id: ownerId }, { token: 'other-token', contributor_id: otherId }];
  const calls = [];
  const context = { app: { post(_path, _limit, callback) { handler = callback; } }, rateLimit() {},
    requireContributor: async () => authenticatedId,
    hasuraAdmin: async (query, values) => {
      calls.push({ query, values });
      const scoped = /contributor_id:\s*\{\s*_eq:\s*\$c\s*\}/.test(query);
      for (let index = rows.length - 1; index >= 0; index--) {
        if (rows[index].token === values.t && (!scoped || rows[index].contributor_id === values.c)) rows.splice(index, 1);
      }
      return { delete_device_tokens: { affected_rows: 1 } };
    } };
  const start = source.indexOf("app.post('/auth/device-token/remove'");
  const end = source.indexOf('// ── Надіслати сповіщення', start);
  assert.ok(start > 0 && end > start);
  vm.runInNewContext(source.slice(start, end), context);
  return { rows, calls, remove: async token => {
    const res = { status(code) { this.code = code; return this; }, json(value) { this.body = value; return this; } };
    await handler({ body: { token } }, res);
    return res;
  } };
}

test('device-token removal leaves another account token intact', async () => {
  const harness = deviceTokenHarness();
  await harness.remove('other-token');
  assert.equal(harness.rows.length, 2);
  assert.equal(harness.calls[0].values.c, ownerId);
});

test('device-token removal still removes the authenticated owner token', async () => {
  const harness = deviceTokenHarness();
  await harness.remove('own-token');
  assert.deepEqual(harness.rows, [{ token: 'other-token', contributor_id: otherId }]);
});

test('unauthenticated or missing-token requests do not delete anything', async () => {
  const anonymous = deviceTokenHarness(null);
  await anonymous.remove('own-token');
  assert.equal(anonymous.calls.length, 0);
  const missing = deviceTokenHarness();
  assert.equal((await missing.remove(undefined)).code, 400);
  assert.equal(missing.calls.length, 0);
});
