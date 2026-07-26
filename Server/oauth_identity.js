'use strict';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function normalizeOAuthEmail(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  if (!normalized || normalized.length > 254 || !EMAIL_RE.test(normalized)) {
    return null;
  }
  return normalized;
}

function googleVerifiedEmail(profile) {
  if (profile?._json?.email_verified === true) {
    const email = normalizeOAuthEmail(profile._json.email);
    if (email) return email;
  }
  const verified = Array.isArray(profile?.emails)
    ? profile.emails.find((entry) => entry?.verified === true)
    : null;
  return normalizeOAuthEmail(verified?.value);
}

function githubVerifiedEmail(profile) {
  const verified = Array.isArray(profile?.emails)
    ? profile.emails.filter((entry) => entry?.verified === true)
    : [];
  const preferred = verified.find((entry) => entry?.primary === true) || verified[0];
  return normalizeOAuthEmail(preferred?.value);
}

function oauthEmailForNewIdentity(value, {
  verified = false,
  allowProviderWithoutEmail = false,
} = {}) {
  const normalized = normalizeOAuthEmail(value);
  if (normalized && verified !== true) {
    throw new Error('oauth_email_not_verified');
  }
  if (!normalized && allowProviderWithoutEmail !== true) {
    throw new Error('oauth_verified_email_required');
  }
  return normalized;
}

module.exports = {
  githubVerifiedEmail,
  googleVerifiedEmail,
  normalizeOAuthEmail,
  oauthEmailForNewIdentity,
};
