'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  classifyUpload,
  decodeBase64Strict,
  normalizeAvatarDataUrl,
  normalizedOrigin,
  passwordPrehash,
  serializeForInlineScript,
  validateNewPassword,
} = require('../security_policy');

function source(relativePath) {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

test('OAuth target origin is canonical and fails closed in production', () => {
  assert.equal(
    normalizedOrigin('https://ostrovua.online/login?source=oauth', { production: true }),
    'https://ostrovua.online'
  );
  assert.equal(
    normalizedOrigin('http://localhost:5500/path', { production: false }),
    'http://localhost:5500'
  );
  assert.throws(
    () => normalizedOrigin('http://ostrovua.online', { production: true }),
    /https/
  );
  assert.throws(() => normalizedOrigin('javascript:alert(1)'), /http/);
});

test('inline JSON cannot terminate the OAuth script element', () => {
  const encoded = serializeForInlineScript({
    name: '</script><script>alert(1)</script>',
    separator: '\u2028',
  });
  assert.doesNotMatch(encoded, /<\/script/i);
  assert.match(encoded, /\\u003c\/script\\u003e/);
  assert.match(encoded, /\\u2028/);
});

test('frontend and callback reject wildcard or unrelated postMessage senders', () => {
  const server = source('server.js');
  const frontend = source('../Frontend/index.html');

  assert.doesNotMatch(server, /postMessage\([^;\n]*,\s*['"]\*['"]\s*\)/);
  assert.match(server, /window\.opener\.postMessage\([^;]+OAUTH_TARGET_ORIGIN|targetOrigin/s);
  assert.match(frontend, /event\.origin !== expectedAuthOrigin/);
  assert.match(frontend, /event\.source !== popup/);
});

test('OAuth state is one-time, host-bound and independent of process memory', () => {
  const server = source('server.js');
  const packageJson = source('package.json');

  assert.match(server, /crypto\.randomBytes\(32\)\.toString\('base64url'\)/);
  assert.match(server, /httpOnly:\s*true/);
  assert.match(server, /sameSite:\s*'lax'/);
  assert.match(server, /timingSafeEqual/);
  assert.match(server, /verifyOAuthState\('google'\)/);
  assert.match(server, /verifyOAuthState\('github'\)/);
  assert.doesNotMatch(server, /require\(['"]express-session['"]\)|passport\.session\(\)/);
  assert.doesNotMatch(packageJson, /express-session/);
});

test('password policy accepts long passphrases and rejects weak/contextual values', () => {
  assert.equal(validateNewPassword('correct horse battery staple').ok, true);
  assert.equal(validateNewPassword('short password').ok, false);
  assert.equal(validateNewPassword('passwordpassword').ok, false);
  assert.equal(
    validateNewPassword('alice@example.com has a strong secret', {
      email: 'alice@example.com',
    }).ok,
    false
  );
  assert.equal(
    passwordPrehash('пароль-пароль-пароль'),
    passwordPrehash('пароль-пароль-пароль')
  );
  assert.notEqual(passwordPrehash('one password'), passwordPrehash('another password'));
});

test('base64 decoder is canonical and rejects permissive decoder edge cases', () => {
  const pngPrefix = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.deepEqual(decodeBase64Strict(pngPrefix.toString('base64')), pngPrefix);
  assert.equal(decodeBase64Strict('YWJjZA'), null);
  assert.equal(decodeBase64Strict('YWJjZA==\n<script>'), null);
  assert.equal(decodeBase64Strict('data:text/html;base64,PGgxPg=='), null);
});

test('upload type is derived from content and active web formats are rejected', () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0]);
  const pdf = Buffer.from('%PDF-1.7\n');
  const html = Buffer.from('<!doctype html><script>alert(1)</script>');
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>');

  assert.deepEqual(classifyUpload(png), {
    extension: 'png',
    mime: 'image/png',
    disposition: 'inline',
  });
  assert.deepEqual(classifyUpload(pdf), {
    extension: 'pdf',
    mime: 'application/pdf',
    disposition: 'attachment',
  });
  assert.equal(classifyUpload(html), null);
  assert.equal(classifyUpload(svg), null);
});

test('avatar data URL requires canonical raster bytes and matching MIME', () => {
  const jpeg = Buffer.from([0xff, 0xd8, 0xff, 0xdb, 0, 1, 2, 3]);
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>');
  const jpegUrl = `data:image/jpeg;base64,${jpeg.toString('base64')}`;

  assert.equal(normalizeAvatarDataUrl(jpegUrl), jpegUrl);
  assert.equal(
    normalizeAvatarDataUrl(`data:image/png;base64,${jpeg.toString('base64')}`),
    null
  );
  assert.equal(
    normalizeAvatarDataUrl(`data:image/svg+xml;base64,${svg.toString('base64')}`),
    null
  );
  assert.equal(normalizeAvatarDataUrl('https://attacker.example/tracker.png'), null);
});

test('upload route ignores user filenames and nginx blocks legacy active extensions', () => {
  const server = source('server.js');
  const nginx = source('nginx/nginx.conf');
  const uploadStart = server.indexOf("app.post('/auth/upload'");
  const uploadEnd = server.indexOf("// ── Дзвінки", uploadStart);
  const route = server.slice(uploadStart, uploadEnd);

  assert.match(route, /classifyUpload\(buf\)/);
  assert.match(route, /uploadType\.extension/);
  assert.doesNotMatch(route, /split\(['"]\.['"]\)|path\.extname\(name/);
  assert.match(nginx, /legacy \.html\/\.svg\/\.js upload/);
  assert.match(nginx, /X-Content-Type-Options\s+"nosniff"/);
  assert.match(nginx, /Content-Security-Policy\s+"default-src 'none'; sandbox"/);
  assert.match(nginx, /location \/files\/ \{\s*return 404;/s);
});

test('avatar rendering and update are restricted to safe image types', () => {
  const server = source('server.js');
  const frontend = source('../Frontend/index.html');
  const routeStart = server.indexOf("app.post('/auth/update-avatar'");
  const routeEnd = server.indexOf('// ── UPDATE THEME', routeStart);
  const route = server.slice(routeStart, routeEnd);

  assert.match(route, /requireContributor\(req, res\)/);
  assert.match(route, /normalizeAvatarDataUrl\(photo_url\)/);
  assert.doesNotMatch(route, /startsWith\(['"]data:image\/['"]\)/);
  assert.match(frontend, /const safeImageUrl =/);
  assert.match(frontend, /data:image\\\/\(\?:jpeg\|png\|webp\)/);
  assert.doesNotMatch(frontend, /src="\$\{esc\(c\.photo_url\)\}"/);
});
