import assert from 'node:assert/strict';
import {createHash, X509Certificate} from 'node:crypto';
import {lstatSync, readFileSync, realpathSync} from 'node:fs';
import path from 'node:path';

// The caller owns this new, disposable fixture and separately authorizes any
// CA import into its Chromium profile. This module never modifies trust.
export function browserFixture(env = process.env) {
  assert.notEqual(env.NODE_TLS_REJECT_UNAUTHORIZED, '0', 'TLS verification cannot be disabled');
  const root = env.GOAUTH_BROWSER_FIXTURE_DIR;
  assert(root && path.isAbsolute(root), 'GOAUTH_BROWSER_FIXTURE_DIR is required and must be absolute');
  assert.equal(realpathSync(root), root, 'fixture directory must be canonical, not a symlink');
  assert(path.basename(root).startsWith('goauth-browser-'), 'a dedicated goauth-browser-* fixture is required');
  assert.equal(typeof process.getuid, 'function', 'browser fixture requires Unix ownership checks');
  const owned = (file, directory) => {
    const stat = lstatSync(file);
    assert.equal(stat.uid, process.getuid(), 'fixture must belong to the current user');
    assert(directory ? stat.isDirectory() : stat.isFile(), 'fixture paths must not be symlinks');
    assert.equal(stat.mode & 0o077, 0, 'fixture paths must not be accessible by other users');
  };
  owned(root, true);
  const manifestFile = path.join(root, 'fixture.json');
  const caFile = path.join(root, 'ca.pem');
  const profile = path.join(root, 'chromium-profile');
  owned(manifestFile, false);
  owned(caFile, false);
  owned(profile, true);
  const manifest = JSON.parse(readFileSync(manifestFile, 'utf8'));
  assert.equal(manifest.version, 1);
  assert.equal(manifest.purpose, 'goauth-browser-acceptance');
  const created = Date.parse(manifest.createdAt), expires = Date.parse(manifest.expiresAt), now = Date.now();
  assert(Number.isFinite(created) && Number.isFinite(expires) && created <= now && now < expires,
    'fixture must be within its explicit test-session validity window');
  const ca = readFileSync(caFile);
  assert.equal(manifest.caHash, createHash('sha256').update(ca).digest('hex'),
    'fixture CA must match its provenance manifest');
  const reuse = env.GOAUTH_BROWSER_REUSE_TRUST_PROFILE;
  const trustPath = env.GOAUTH_BROWSER_TRUST_PROFILE;
  const approvedHash = env.GOAUTH_BROWSER_TRUST_CA_SHA256;
  if (reuse === undefined && trustPath === undefined && approvedHash === undefined)
    return {ca, profile, expiresAt: expires};
  assert.equal(reuse, '1', 'reusable trust requires explicit opt-in');
  assert(trustPath && path.isAbsolute(trustPath), 'dedicated trust profile must be absolute');
  assert.equal(realpathSync(trustPath), trustPath, 'trust profile must be canonical and contain no symlink components');
  assert(path.basename(trustPath).startsWith('goauth-browser-trust-'), 'dedicated trust profile required');
  owned(trustPath, true);
  assert.equal(lstatSync(trustPath).mode & 0o777, 0o700, 'trust profile must be mode 0700');
  const markerPath = path.join(trustPath, 'goauth-trust-profile.json');
  owned(markerPath, false);
  assert.equal(lstatSync(markerPath).mode & 0o777, 0o600, 'trust marker must be mode 0600');
  const marker = JSON.parse(readFileSync(markerPath, 'utf8'));
  assert.equal(marker.version, 1);
  assert.equal(marker.purpose, 'goauth-browser-reusable-trust');
  assert(/^[a-f0-9]{64}$/.test(approvedHash || ''), 'explicit approved CA SHA-256 required');
  assert.equal(marker.caHash, approvedHash, 'trust marker must match the approved CA');
  const certificate = new X509Certificate(ca);
  assert(certificate.ca, 'approved certificate must be a CA');
  assert.equal(createHash('sha256').update(certificate.raw).digest('hex'), approvedHash,
    'fixture CA DER fingerprint must match the approved CA');
  const trustCreated = Date.parse(marker.createdAt), trustExpires = Date.parse(marker.expiresAt);
  const caStart = Date.parse(certificate.validFrom), caExpires = Date.parse(certificate.validTo);
  assert(Number.isFinite(trustCreated) && Number.isFinite(trustExpires) &&
    Number.isFinite(caStart) && Number.isFinite(caExpires) &&
    caStart <= now && trustCreated <= now && now + 150000 <= trustExpires &&
    trustExpires <= caExpires, 'trust profile must remain within its CA validity for the test deadline');
  return {ca, profile: trustPath, expiresAt: Math.min(expires, trustExpires), reusableTrust: true};
}

export function secureBrowserOptions(executablePath) {
  return {headless: true, executablePath, chromiumSandbox: true,
    ignoreHTTPSErrors: false, args: ['--no-proxy-server']};
}

// A reusable profile carries trust only. Authentication pages always use a fresh
// off-the-record context, and both contexts are closed even after a failure.
export async function launchBrowserSession(chromium, fixture, executablePath) {
  const parent = await chromium.launchPersistentContext(fixture.profile, secureBrowserOptions(executablePath));
  if (!fixture.reusableTrust) return {context: parent, close: () => parent.close()};
  let context;
  try {
    const browser = parent.browser();
    assert(browser, 'persistent trust profile must provide a browser');
    context = await browser.newContext({ignoreHTTPSErrors: false});
    assert.deepEqual(await context.storageState(), {cookies: [], origins: []}, 'test context must start without stored state');
    assert.equal(context.pages().length, 0, 'test context must start without pages');
    return {context, close: async () => { try { await context.close(); } finally { await parent.close(); } }};
  } catch (error) {
    try { if (context) await context.close(); } finally { await parent.close(); }
    throw error;
  }
}

export function browserOrigin(value) {
  const url = new URL(value);
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, 'localhost');
  assert(url.port && Number(url.port) > 0, 'fixture needs an explicit local port');
  assert.equal(url.username + url.password + url.search + url.hash, '');
  assert.equal(url.pathname, '/');
  return {origin: url.origin, port: url.port, hostile: `https://127.0.0.1:${url.port}`};
}

export function secureRequestOptions(ca, port, requestPath, method, headers) {
  return {hostname: '127.0.0.1', port, servername: 'localhost', ca,
    rejectUnauthorized: true, path: requestPath, method,
    headers: {Host: `localhost:${port}`, 'Content-Type': 'application/json', ...headers}};
}

export function assertFixtureActive(expiresAt, now = Date.now()) {
  assert(Number.isFinite(expiresAt) && now < expiresAt,
    'fixture validity expired before reporting browser acceptance');
}
