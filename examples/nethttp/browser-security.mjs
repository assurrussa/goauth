import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
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
  return {ca, profile};
}

export function secureBrowserOptions(executablePath) {
  return {headless: true, executablePath, chromiumSandbox: true,
    ignoreHTTPSErrors: false, args: ['--no-proxy-server']};
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
