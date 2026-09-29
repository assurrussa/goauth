import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const expiryKey = 'goauth-access-expiry';
const blockedKey = 'goauth-refresh-blocked';

function serializedLocks() {
  let tail = Promise.resolve();
  return {
    request(name, callback) {
      assert.equal(name, 'goauth-refresh');
      const result = tail.then(callback);
      tail = result.catch(() => {});
      return result;
    },
  };
}

function browser({storage = new Map(), locks = serializedLocks(), respond} = {}) {
  const elements = new Map();
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', listeners: {},
      addEventListener(type, handler) { this.listeners[type] = handler; },
    });
    return elements.get(id);
  }
  const calls = [];
  const context = vm.createContext({
    document: {querySelector: element, getElementById: element},
    navigator: {locks},
    location: {hash: '', pathname: '/'},
    localStorage: {
      getItem: key => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, String(value)),
      removeItem: key => storage.delete(key),
    },
    async fetch(path, options) {
      const action = path.replace('/browser/', '');
      calls.push(action);
      assert.equal(options.credentials, 'same-origin');
      assert.equal(options.headers['X-Goauth-CSRF'], '1');
      if (respond) return respond(action, options);
      return action === 'refresh'
        ? Response.json({accessExpiresAt: new Date(Date.now() + 300_000).toISOString()})
        : new Response(null, {status: 204});
    },
  });
  vm.runInContext(source, context, {filename: 'app.js'});
  return {context, calls, storage, elements};
}

function currentStorage() {
  return new Map([[expiryKey, new Date(Date.now() + 300_000).toISOString()]]);
}

for (const action of ['logout', 'logout-all']) {
  test(`${action} refreshes expired access before server revocation`, async () => {
    const page = browser();
    await page.context.logout(action);
    assert.deepEqual(page.calls, ['refresh', action]);
    assert.equal(page.storage.get(expiryKey), undefined);
    assert.equal(page.storage.get(blockedKey), '1');
    await page.context.refresh();
    assert.deepEqual(page.calls, ['refresh', action]);
  });

  test(`${action} does not rotate a current access cookie`, async () => {
    const page = browser({storage: currentStorage()});
    await page.context.logout(action);
    assert.deepEqual(page.calls, [action]);
    assert.equal(page.storage.get(expiryKey), undefined);
  });
}

test('refresh, logout and a queued refresh across tabs share one critical section', async () => {
  const storage = new Map();
  const locks = serializedLocks();
  const first = browser({storage, locks});
  const second = browser({storage, locks});
  await Promise.all([first.context.refresh(), second.context.logout(), first.context.refresh()]);
  assert.deepEqual(first.calls, ['refresh']);
  assert.deepEqual(second.calls, ['logout']);
  assert.equal(storage.get(blockedKey), '1');
});

test('failed refresh prevents logout and is not retried by another click', async () => {
  const page = browser({respond: () => Response.json({error: {code: 'unavailable'}}, {status: 503})});
  await page.context.logout();
  await page.context.logout();
  assert.deepEqual(page.calls, ['refresh']);
  assert.equal(page.storage.get(blockedKey), '1');
});

test('lost refresh response prevents blind resubmission and does not claim logout', async () => {
  const page = browser({respond: () => { throw new Error('response lost'); }});
  await page.context.logout();
  await page.context.refresh();
  assert.deepEqual(page.calls, ['refresh']);
  assert.equal(page.storage.get(blockedKey), '1');
});

test('lost logout response blocks queued refresh and reports uncertainty', async () => {
  const page = browser({storage: currentStorage(), respond: () => { throw new Error('response lost'); }});
  await page.context.logout();
  assert.match(page.elements.get('#result').textContent, /revocation was not confirmed/);
  await page.context.refresh();
  assert.deepEqual(page.calls, ['logout']);
  assert.equal(page.storage.get(blockedKey), '1');
});

test('failed logout response also blocks queued refresh', async () => {
  const page = browser({storage: currentStorage(), respond: () => Response.json({}, {status: 503})});
  assert.equal((await page.context.logout()).status, 503);
  await page.context.refresh();
  assert.deepEqual(page.calls, ['logout']);
});

test('missing Web Locks never falls back to an unsafe concurrent request', async () => {
  const page = browser({locks: null});
  await page.context.logout();
  await page.context.refresh();
  assert.deepEqual(page.calls, []);
});

test('a successful new login clears the previous logout block', async () => {
  const storage = new Map([[blockedKey, '1']]);
  const page = browser({storage, respond: action => action === 'login'
    ? Response.json({accessExpiresAt: new Date(Date.now() + 300_000).toISOString()})
    : new Response(null, {status: 204})});
  await page.context.request('login');
  await page.context.logout();
  assert.deepEqual(page.calls, ['login', 'logout']);
});

test('logout buttons use the coordinator rather than issuing a raw logout', async () => {
  const page = browser();
  await page.elements.get('logout').listeners.click();
  assert.deepEqual(page.calls, ['refresh', 'logout']);
});

test('successful refresh without expiry metadata cannot unlock a logout', async () => {
  const page = browser({respond: () => Response.json({})});
  await page.context.logout();
  assert.deepEqual(page.calls, ['refresh']);
  assert.equal(page.storage.get(blockedKey), '1');
});

test('logout rejects unrelated action names', async () => {
  const page = browser();
  await assert.rejects(page.context.logout('password'), /Invalid logout action/);
  assert.deepEqual(page.calls, []);
});
