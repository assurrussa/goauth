import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {browserFixture, browserOrigin, secureBrowserOptions, secureRequestOptions} from './browser-security.mjs';

function fixture(t) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'goauth-browser-')));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  chmodSync(root, 0o700);
  mkdirSync(path.join(root, 'chromium-profile'), {mode: 0o700});
  const ca = Buffer.from('synthetic fixture CA bytes for configuration-only tests');
  writeFileSync(path.join(root, 'ca.pem'), ca, {mode: 0o600});
  const manifest = {version: 1, purpose: 'goauth-browser-acceptance',
    createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), caHash: createHash('sha256').update(ca).digest('hex')};
  const save = () => writeFileSync(path.join(root, 'fixture.json'), JSON.stringify(manifest), {mode: 0o600});
  save();
  return {root, ca, manifest, save, env: {GOAUTH_BROWSER_FIXTURE_DIR: root}};
}

test('secure browser and request options retain TLS verification and Chromium sandbox', () => {
  const options = secureBrowserOptions('/synthetic/chromium');
  assert.equal(options.chromiumSandbox, true);
  assert.equal(options.ignoreHTTPSErrors, false);
  assert.deepEqual(options.args, ['--no-proxy-server']);
  const ca = Buffer.from('synthetic CA');
  const request = secureRequestOptions(ca, '443', '/fixture/stats', 'GET', {});
  assert.equal(request.rejectUnauthorized, true);
  assert.equal(request.ca, ca);
  assert.equal(request.servername, 'localhost');
  assert.equal(request.hostname, '127.0.0.1');
  assert.equal(request.checkServerIdentity, undefined, 'normal hostname verification must remain enabled');
});

test('origin cannot leave the explicit loopback HTTPS fixture', () => {
  assert.deepEqual(browserOrigin('https://localhost:12345'),
    {origin: 'https://localhost:12345', port: '12345', hostile: 'https://127.0.0.1:12345'});
  for (const origin of ['http://localhost:12345', 'https://other.example:12345',
    'https://user@localhost:12345', 'https://localhost:12345/path', 'https://localhost:12345/?token=x']) {
    assert.throws(() => browserOrigin(origin));
  }
});

test('fixture requires explicit fresh owned provenance and the same CA', t => {
  const f = fixture(t);
  assert.deepEqual(browserFixture(f.env), {ca: f.ca, profile: path.join(f.root, 'chromium-profile')});
  assert.throws(() => browserFixture({}), /GOAUTH_BROWSER_FIXTURE_DIR/);
  assert.throws(() => browserFixture({...f.env, NODE_TLS_REJECT_UNAUTHORIZED: '0'}), /disabled/);
  f.manifest.caHash = '0'.repeat(64); f.save();
  assert.throws(() => browserFixture(f.env), /provenance/);
  f.manifest.caHash = createHash('sha256').update(f.ca).digest('hex');
  f.manifest.expiresAt = new Date(Date.now() - 1000).toISOString(); f.save();
  assert.throws(() => browserFixture(f.env), /validity window/);
});

test('profile symlinks and shared fixture permissions are rejected', t => {
  const f = fixture(t);
  const profile = path.join(f.root, 'chromium-profile');
  rmSync(profile, {recursive: true});
  symlinkSync(os.tmpdir(), profile);
  assert.throws(() => browserFixture(f.env), /symlinks/);
  rmSync(profile); mkdirSync(profile, {mode: 0o700});
  chmodSync(f.root, 0o755);
  assert.throws(() => browserFixture(f.env), /other users/);
});

test('acceptance source cannot silently restore TLS or sandbox bypasses', () => {
  const source = readFileSync(new URL('./browser-acceptance.mjs', import.meta.url), 'utf8') +
    readFileSync(new URL('./browser-security.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /rejectUnauthorized\s*:\s*false|ignoreHTTPSErrors\s*:\s*true|chromiumSandbox\s*:\s*false/);
  assert.doesNotMatch(source, /--no-sandbox|--disable-setuid-sandbox|--ignore-certificate-errors|--allow-insecure-localhost/);
  assert.match(source, /launchPersistentContext\(fixture\.profile,secureBrowserOptions/);
});
