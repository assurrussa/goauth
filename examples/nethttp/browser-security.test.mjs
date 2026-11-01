import assert from 'node:assert/strict';
import {createHash, X509Certificate} from 'node:crypto';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {assertFixtureActive, browserFixture, browserOrigin, launchBrowserSession, secureBrowserOptions, secureRequestOptions} from './browser-security.mjs';

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
  assert.deepEqual(browserFixture(f.env), {ca: f.ca, profile: path.join(f.root, 'chromium-profile'), expiresAt: Date.parse(f.manifest.expiresAt)});
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
  unlinkSync(profile); mkdirSync(profile, {mode: 0o700});
  chmodSync(f.root, 0o755);
  assert.throws(() => browserFixture(f.env), /other users/);
});

test('acceptance source cannot silently restore TLS or sandbox bypasses', () => {
  const source = readFileSync(new URL('./browser-acceptance.mjs', import.meta.url), 'utf8') +
    readFileSync(new URL('./browser-security.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /rejectUnauthorized\s*:\s*false|ignoreHTTPSErrors\s*:\s*true|chromiumSandbox\s*:\s*false/);
  assert.doesNotMatch(source, /--no-sandbox|--disable-setuid-sandbox|--ignore-certificate-errors|--allow-insecure-localhost/);
  assert.match(source, /launchBrowserSession\(chromium,fixture/);
  assert.match(source, /launchPersistentContext\(fixture\.profile, secureBrowserOptions/);
});

test('an expired fixture cannot report browser acceptance', () => {
  assert.doesNotThrow(() => assertFixtureActive(2000, 1999));
  assert.throws(() => assertFixtureActive(2000, 2000), /expired/);
  assert.throws(() => assertFixtureActive(2000, 2072), /expired/);
});

const publicTestCA = `-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIUSgBXSQpVAT+obOWoFJ4FXx/Pi+IwDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYc3ludGhldGljIHVuaXQgdGVzdCBvbmx5MB4XDTI2MTEw
MTE5NTkwM1oXDTM2MTAyOTE5NTkwM1owIzEhMB8GA1UEAwwYc3ludGhldGljIHVu
aXQgdGVzdCBvbmx5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwjpl
EmuIiFW1KabJYPryXBeFWCF/keHrwUK5dPy2N3HHvJ2Q2Z5fDZivCQ1SJIJ8bfT4
9FUQvZE7k9tJS7ygNqpTeScLSRsMZJdkuqMxhjntdFpu5u966XHosf6mOcltsH6F
VL35BdRvXVuwEXDCY5S0lgRVFxxVpZzbEI6SpfLBJQ7dEBCbgkX2HkktXAhEQNOO
lGTqmU5Us3USzsxcKZG9qnzLa35znY7V7GJgihrHKo4iJnz4Gi8eQqtHY4wQQtzq
H3D82GcvoX1Gl9VQFexHxgC+ZJZ2a/3M0rrrvEXC5Vgka+Hxlm/if7xCiIHoXaB6
yTacaFxjMPMbh/z2HwIDAQABo1MwUTAdBgNVHQ4EFgQUzYOi1pqyGwynVsnXHElL
5S6937QwHwYDVR0jBBgwFoAUzYOi1pqyGwynVsnXHElL5S6937QwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZ7RoCHvMBTYMpFjijZ1imj7tDAgy
JB1ulwJSPYc/VUuKCIetx6xXQ5KJHTWvGS3iJP7Uf/zYlsPw22RbsypFSujOAdnA
KaBqKAL00yiw5l95IL061B9l6BsWEG1ibO0HTOsZw9tmY62qvUiQ+noX8FRkZ0sm
nU6nrB50j6h2cxFIiVpPkxmA4ZcLCMdJxug0nuyI231VRwz1Xz9NH7QE35Opjv6z
yzMuVLMvfTbhkNwHDsigJSap+ApIU9tXxbS96iX7GTMFCy8bW/lmjw819u5yvhTs
uRbMzXBpbnwgQe/mrzj/6FHA2DSnXV8QOtsLAwHBAK2GqI/dzu/7EL/Vxw==
-----END CERTIFICATE-----\n`;

function reusableFixture(t) {
  const f = fixture(t);
  writeFileSync(path.join(f.root, 'ca.pem'), publicTestCA, {mode: 0o600});
  f.manifest.caHash = createHash('sha256').update(publicTestCA).digest('hex');
  f.save();
  const trust = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'goauth-browser-trust-')));
  t.after(() => rmSync(trust, {recursive: true, force: true}));
  chmodSync(trust, 0o700);
  const marker = {version: 1, purpose: 'goauth-browser-reusable-trust',
    caHash: createHash('sha256').update(new X509Certificate(publicTestCA).raw).digest('hex'), createdAt: new Date(Date.now()-1000).toISOString(),
    expiresAt: new Date(Date.now()+60*60*1000).toISOString()};
  const saveMarker = () => writeFileSync(path.join(trust, 'goauth-trust-profile.json'), JSON.stringify(marker), {mode: 0o600});
  saveMarker();
  return {...f, trust, marker, saveMarker, env: {...f.env, GOAUTH_BROWSER_REUSE_TRUST_PROFILE: '1',
    GOAUTH_BROWSER_TRUST_PROFILE: trust, GOAUTH_BROWSER_TRUST_CA_SHA256: marker.caHash}};
}

test('reusable trust requires explicit owned marker, approved CA and bounded expiry', t => {
  const f = reusableFixture(t);
  const accepted = browserFixture(f.env);
  assert.equal(accepted.profile, f.trust);
  assert.equal(accepted.reusableTrust, true);
  for (const invalid of [
    {...f.env, GOAUTH_BROWSER_REUSE_TRUST_PROFILE: undefined},
    {...f.env, GOAUTH_BROWSER_TRUST_CA_SHA256: '0'.repeat(64)},
    {...f.env, GOAUTH_BROWSER_TRUST_PROFILE: path.join(f.root, 'chromium-profile')},
  ]) assert.throws(() => browserFixture(invalid));
  f.marker.caHash = '0'.repeat(64); f.saveMarker();
  assert.throws(() => browserFixture(f.env), /approved CA/);
  f.marker.caHash = 'f'.repeat(64); f.saveMarker();
  assert.throws(() => browserFixture({...f.env, GOAUTH_BROWSER_TRUST_CA_SHA256: f.marker.caHash}), /DER fingerprint/);
  f.marker.caHash = f.env.GOAUTH_BROWSER_TRUST_CA_SHA256;
  f.marker.purpose = 'personal'; f.saveMarker();
  assert.throws(() => browserFixture(f.env));
  f.marker.purpose = 'goauth-browser-reusable-trust';
  f.marker.expiresAt = new Date(Date.now()-1).toISOString(); f.saveMarker();
  assert.throws(() => browserFixture(f.env), /validity/);
  f.marker.expiresAt = new Date(Date.now()+149000).toISOString(); f.saveMarker();
  assert.throws(() => browserFixture(f.env), /validity/);
  f.marker.expiresAt = new Date('2100-01-01T00:00:00Z').toISOString(); f.saveMarker();
  assert.throws(() => browserFixture(f.env), /validity/);
  f.marker.expiresAt = new Date(Date.now()+60*60*1000).toISOString(); f.saveMarker();
  chmodSync(f.trust, 0o755);
  assert.throws(() => browserFixture(f.env), /other users/);
});

test('reusable trust rejects symlink and shared marker modes', t => {
  const f = reusableFixture(t);
  const link = path.join(f.root, 'goauth-browser-trust-link');
  symlinkSync(f.trust, link);
  assert.throws(() => browserFixture({...f.env, GOAUTH_BROWSER_TRUST_PROFILE: link}), /canonical/);
  chmodSync(path.join(f.trust, 'goauth-trust-profile.json'), 0o644);
  assert.throws(() => browserFixture(f.env), /other users/);
});

test('default remains fresh persistent context; opt-in uses only isolated child and closes both', async () => {
  const calls = [];
  const child = {newPage() { calls.push('child-page'); }, pages() { return []; }, async storageState() { return {cookies: [], origins: []}; }, async close() { calls.push('child-close'); }};
  const parent = {newPage() { throw new Error('auth must not use persistent parent'); },
    browser() { return {async newContext(options) { calls.push(['newContext', options]); return child; }}; },
    async close() { calls.push('parent-close'); }};
  const chromium = {async launchPersistentContext(profile, options) { calls.push(['launch', profile, options]); return parent; }};
  const normal = await launchBrowserSession(chromium, {profile: '/fresh'}, '/browser');
  assert.equal(normal.context, parent);
  await normal.close();
  assert.deepEqual(calls.map(c => Array.isArray(c) ? c[0] : c), ['launch', 'parent-close']);
  calls.length = 0;
  const isolated = await launchBrowserSession(chromium, {profile: '/trust', reusableTrust: true}, '/browser');
  assert.equal(isolated.context, child);
  assert.deepEqual(calls[1], ['newContext', {ignoreHTTPSErrors: false}]);
  isolated.context.newPage();
  await isolated.close();
  assert.deepEqual(calls.map(c => Array.isArray(c) ? c[0] : c), ['launch', 'newContext', 'child-page', 'child-close', 'parent-close']);
  assert.equal(calls[0][2].chromiumSandbox, true);
  assert.equal(calls[0][2].ignoreHTTPSErrors, false);
});

test('failed isolated creation or close still closes the persistent parent', async () => {
  const calls = [];
  const parent = {browser() { return {async newContext() { throw new Error('creation failed'); }}; }, async close() { calls.push('parent'); }};
  await assert.rejects(launchBrowserSession({async launchPersistentContext() { return parent; }}, {profile: '/trust', reusableTrust: true}), /creation failed/);
  assert.deepEqual(calls, ['parent']);
  const child = {pages() { return []; }, async storageState() { return {cookies: [], origins: []}; }, async close() { calls.push('child'); throw new Error('close failed'); }};
  parent.browser = () => ({async newContext() { return child; }});
  const session = await launchBrowserSession({async launchPersistentContext() { return parent; }}, {profile: '/trust', reusableTrust: true});
  await assert.rejects(session.close(), /close failed/);
  assert.deepEqual(calls, ['parent', 'child', 'parent']);
});



test('refuses a non-empty isolated context and closes both contexts', async () => {
  const calls = [];
  const child = {pages() { return []; }, async storageState() { return {cookies: [{name: 'unexpected'}], origins: []}; }, async close() { calls.push('child'); }};
  const parent = {browser() { return {async newContext() { return child; }}; }, async close() { calls.push('parent'); }};
  await assert.rejects(launchBrowserSession({async launchPersistentContext() { return parent; }}, {profile: '/trust', reusableTrust: true}), /without stored state/);
  assert.deepEqual(calls, ['child', 'parent']);
});
