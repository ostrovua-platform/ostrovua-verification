'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  githubVerifiedEmail,
  googleVerifiedEmail,
  normalizeOAuthEmail,
  oauthEmailForNewIdentity,
} = require('../oauth_identity');

test('Google identity accepts only an explicitly verified email', () => {
  assert.equal(googleVerifiedEmail({
    _json: { email: ' User@Example.COM ', email_verified: true },
  }), 'user@example.com');
  assert.equal(googleVerifiedEmail({
    _json: { email: 'victim@example.com', email_verified: false },
    emails: [{ value: 'victim@example.com' }],
  }), null);
  assert.equal(googleVerifiedEmail({
    emails: [{ value: 'verified@example.com', verified: true }],
  }), 'verified@example.com');
});

test('GitHub identity accepts only a verified email and prefers primary', () => {
  assert.equal(githubVerifiedEmail({
    emails: [
      { value: 'unverified@example.com', primary: true, verified: false },
      { value: 'secondary@example.com', verified: true },
      { value: 'primary@example.com', primary: true, verified: true },
    ],
  }), 'primary@example.com');
  assert.equal(githubVerifiedEmail({
    emails: [{ value: 'victim@example.com', primary: true }],
  }), null);
});

test('OAuth email normalization is canonical', () => {
  assert.equal(normalizeOAuthEmail(' User@Example.COM '), 'user@example.com');
  assert.equal(normalizeOAuthEmail('not-an-email'), null);
  assert.equal(normalizeOAuthEmail(null), null);
});

test('new OAuth identity cannot select an account by unverified email', () => {
  assert.throws(
    () => oauthEmailForNewIdentity('victim@example.com', { verified: false }),
    /oauth_email_not_verified/
  );
  assert.throws(
    () => oauthEmailForNewIdentity(null),
    /oauth_verified_email_required/
  );
  assert.equal(
    oauthEmailForNewIdentity(null, { allowProviderWithoutEmail: true }),
    null
  );
});
