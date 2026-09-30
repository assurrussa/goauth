import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createServer} from 'node:http';
import {once} from 'node:events';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('./app.js', import.meta.url), 'utf8');
const expiryKey = 'goauth-access-expiry';
const blockedKey = 'goauth-refresh-blocked';
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
const tokens = () => Response.json({accessExpiresAt: new Date(Date.now() + 300_000).toISOString()});
const currentStorage = (remaining = 300_000) => new Map([[expiryKey, new Date(Date.now() + remaining).toISOString()]]);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

// Model FIFO exclusive locks and cancellation of queued (not acquired) requests.
function serializedLocks() {
  const queue = [];
  let active = false;
  function drain() {
    if (active || !queue.length) return;
    const entry = queue.shift();
    if (entry.signal?.aborted) { drain(); return; }
    active = true;
    entry.signal?.removeEventListener('abort', entry.abort);
    Promise.resolve().then(entry.callback).then(entry.resolve, entry.reject).finally(() => {
      active = false;
      drain();
    });
  }
  return {
    request(name, options, callback) {
      assert.equal(name, 'goauth-refresh');
      if (typeof options === 'function') { callback = options; options = {}; }
      return new Promise((resolve, reject) => {
        const signal = options.signal;
        if (signal?.aborted) { reject(signal.reason); return; }
        const entry = {callback, signal, resolve, reject};
        entry.abort = () => {
          const index = queue.indexOf(entry);
          if (index >= 0) queue.splice(index, 1);
          reject(signal.reason);
        };
        signal?.addEventListener('abort', entry.abort, {once: true});
        queue.push(entry);
        drain();
      });
    },
  };
}

// Deterministically fire the application's actual deadlines without sleeping or
// changing source constants. Aborted fetch/body fixtures honor the actual signal.
function timers() {
  const tasks = new Map();
  let id = 0;
  return {
    setTimeout(fn, ms) { tasks.set(++id, {fn, ms}); return id; },
    clearTimeout(key) { tasks.delete(key); },
    fire(ms) {
      const selected = [...tasks].filter(([, task]) => task.ms === ms);
      assert(selected.length > 0, `deadline ${ms} was not scheduled`);
      for (const [key, task] of selected) { tasks.delete(key); task.fn(); }
    },
    count(ms) { return [...tasks.values()].filter(task => task.ms === ms).length; },
  };
}

function waitForAbort(signal) {
  assert(signal, 'fetch must receive AbortSignal');
  return new Promise((resolve, reject) => {
    if (signal.aborted) reject(signal.reason);
    else signal.addEventListener('abort', () => reject(signal.reason), {once: true});
  });
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
  const clock = timers();
  const context = vm.createContext({
    document: {querySelector: element, getElementById: element},
    navigator: {locks}, location: {hash: '', pathname: '/'}, AbortController,
    setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout,
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
      if (['refresh', 'login', 'register'].includes(action)) return tokens();
      if (action === 'forget-session') return Response.json({browserCredentialsCleared: true, serverSessionsRevoked: false});
      return new Response(null, {status: 204});
    },
  });
  vm.runInContext(source, context, {filename: 'app.js'});
  return {context, calls, storage, elements, clock};
}

for (const action of ['logout', 'logout-all']) {
  test(`${action}: expired access rotates once before revocation`, async () => {
    const page = browser();
    assert.equal((await page.context.logout(action)).status, 204);
    assert.deepEqual(page.calls, ['refresh', action]);
    assert(!page.storage.has(expiryKey));
    assert.equal(page.storage.get(blockedKey), '1');
    await page.context.refresh();
    assert.deepEqual(page.calls, ['refresh', action]);
  });

  test(`${action}: current access does not rotate`, async () => {
    const page = browser({storage: currentStorage()});
    assert.equal((await page.context.logout(action)).status, 204);
    assert.deepEqual(page.calls, [action]);
  });

  test(`review: ${action} with 20 seconds of live access does not require proactive refresh`, async () => {
    const page = browser({storage: currentStorage(20_000), respond: action => action === 'refresh'
      ? Response.json({}, {status: 503}) : new Response(null, {status: 204})});
    assert.equal((await page.context.logout(action))?.status, 204);
    assert.deepEqual(page.calls, [action]);
  });

  test(`review: ${action} can be explicitly retried after known 503`, async () => {
    let attempts = 0;
    const page = browser({storage: currentStorage(), respond: () => ++attempts === 1
      ? Response.json({error: {code: 'authentication_unavailable'}}, {status: 503})
      : new Response(null, {status: 204})});
    assert.equal((await page.context.logout(action)).status, 503);
    await page.context.refresh();
    assert.deepEqual(page.calls, [action], 'refresh remains blocked');
    assert.equal((await page.context.logout(action))?.status, 204);
    assert.deepEqual(page.calls, [action, action]);
  });
}

test('refresh-only block does not prevent logout with live access', async () => {
  const storage = currentStorage();
  storage.set(blockedKey, '1');
  const page = browser({storage});
  assert.equal((await page.context.logout()).status, 204);
  assert.deepEqual(page.calls, ['logout']);
});

test('failed refresh with expired access is never replayed by logout or raw request', async () => {
  const page = browser({respond: () => Response.json({}, {status: 503})});
  await page.context.logout();
  await page.context.logout();
  await page.context.request('refresh');
  assert.deepEqual(page.calls, ['refresh']);
  assert.match(page.elements.get('#result').textContent, /blocked/);
});

test('lost logout response allows explicit revocation retry, never refresh replay', async () => {
  let attempts = 0;
  const page = browser({storage: currentStorage(), respond: () => {
    if (++attempts === 1) throw new Error('response lost');
    return new Response(null, {status: 204});
  }});
  await page.context.logout();
  assert.match(page.elements.get('#result').textContent, /not confirmed/);
  await page.context.refresh();
  assert.equal((await page.context.logout()).status, 204);
  assert.deepEqual(page.calls, ['logout', 'logout']);
});

test('tabs serialize refresh then logout and block the queued refresh', async () => {
  const storage = new Map(), locks = serializedLocks();
  const first = browser({storage, locks}), second = browser({storage, locks});
  await Promise.all([first.context.refresh(), second.context.logout(), first.context.refresh()]);
  assert.deepEqual(first.calls, ['refresh']);
  assert.deepEqual(second.calls, ['logout']);
  assert(!storage.has(expiryKey));
});

for (const action of ['login', 'register']) {
  test(`review: pending ${action} finishes before queued logout, not after it`, async () => {
    const storage = currentStorage(), locks = serializedLocks(), response = deferred();
    const first = browser({storage, locks, respond: () => response.promise});
    const second = browser({storage, locks});
    const login = first.context.request(action);
    await nextTurn();
    const logout = second.context.logout();
    await nextTurn();
    try { assert.deepEqual(second.calls, [], 'logout must wait for the prior issuer response'); }
    finally { response.resolve(tokens()); await Promise.all([login, logout]); }
    assert.deepEqual(first.calls, [action]);
    assert.deepEqual(second.calls, ['logout']);
    assert.equal(storage.get(blockedKey), '1');
    assert(!storage.has(expiryKey));
  });
}

test('a new login after completed logout is allowed', async () => {
  const page = browser({storage: currentStorage()});
  await page.context.logout();
  await page.context.request('login');
  assert(!page.storage.has(blockedKey));
  assert(page.storage.has(expiryKey));
  assert.deepEqual(page.calls, ['logout', 'login']);
});

test('lock stays held through login response body consumption', async () => {
  const storage = currentStorage(), locks = serializedLocks(), body = deferred();
  const first = browser({storage, locks, respond: () => ({ok: true, status: 200, text: () => body.promise})});
  const second = browser({storage, locks});
  const login = first.context.request('login');
  await nextTurn();
  const logout = second.context.logout();
  await nextTurn();
  try { assert.deepEqual(second.calls, []); }
  finally {
    body.resolve(JSON.stringify({accessExpiresAt: new Date(Date.now() + 300_000).toISOString()}));
    await Promise.all([login, logout]);
  }
  assert.equal(storage.get(blockedKey), '1');
});

for (const phase of ['headers', 'body']) {
  test(`review: ${phase} timeout aborts fetch and frees the lock without replaying refresh`, async () => {
    let signal;
    const page = browser({respond: (action, options) => {
      if (action !== 'refresh') return tokens();
      signal = options.signal;
      if (phase === 'headers') return waitForAbort(signal);
      return {ok: true, status: 200, text: () => waitForAbort(signal)};
    }});
    const refresh = page.context.refresh();
    await nextTurn();
    assert(signal, 'fetch must receive AbortSignal');
    assert.equal(page.clock.count(15000), 0, 'lock-wait timer stops at acquisition');
    page.clock.fire(10000);
    await refresh;
    assert(signal.aborted);
    await page.context.logout();
    assert.deepEqual(page.calls, ['refresh']);
    await page.context.request('login');
    assert.deepEqual(page.calls, ['refresh', 'login'], 'canceled request released the lock');
    assert(!page.storage.has(blockedKey));
  });
}

test('queued lock deadline sends nothing and never runs callback after release', async () => {
  const locks = serializedLocks(), held = deferred();
  const holder = locks.request('goauth-refresh', () => held.promise);
  const page = browser({locks, storage: currentStorage()});
  const waiting = page.context.logout();
  await nextTurn();
  page.clock.fire(15000);
  await waiting;
  assert.match(page.elements.get('#result').textContent, /No request was sent/);
  assert.deepEqual(page.calls, []);
  assert(!page.storage.has(blockedKey));
  held.resolve();
  await holder;
  await nextTurn();
  assert.deepEqual(page.calls, []);
  assert.equal((await page.context.logout()).status, 204);
});

for (const expiry of [undefined, 'not-a-date', new Date(0).toISOString()]) {
  test(`invalid refreshed expiry ${expiry} cannot unblock another refresh`, async () => {
    const page = browser({respond: () => Response.json({accessExpiresAt: expiry})});
    await page.context.logout();
    await page.context.refresh();
    assert.deepEqual(page.calls, ['refresh']);
    assert.equal(page.storage.get(blockedKey), '1');
  });
}

test('local forget is explicit and does not claim server revocation', async () => {
  const storage = new Map([[blockedKey, '1']]);
  const page = browser({storage});
  const response = await page.context.request('forget-session');
  assert.equal(response.status, 200);
  assert.deepEqual(page.calls, ['forget-session']);
  assert.match(page.elements.get('#result').textContent, /"serverSessionsRevoked": false/);
  assert(!storage.has(expiryKey));
  await page.context.refresh();
  assert.deepEqual(page.calls, ['forget-session']);
});

test('missing Web Locks rejects session mutations without an unsafe fallback', async () => {
  const page = browser({locks: null});
  for (const action of ['login', 'register', 'refresh', 'logout', 'logout-all', 'forget-session']) await page.context.request(action);
  assert.deepEqual(page.calls, []);
});

test('logout and forget buttons use coordinated operations', async () => {
  const page = browser({storage: currentStorage()});
  await page.elements.get('logout').listeners.click();
  await page.elements.get('forget-session').listeners.click();
  assert.deepEqual(page.calls, ['logout', 'forget-session']);
});

test('logout rejects unrelated actions', async () => {
  const page = browser();
  await assert.rejects(page.context.logout('password'), /Invalid logout action/);
  assert.deepEqual(page.calls, []);
});

// Exercise the same AbortController against Node's real fetch/HTTP body stream,
// not only signal-aware response doubles. This is still not Chromium acceptance.
for (const phase of ['headers', 'body']) {
  test(`native fetch cancels stalled ${phase} on the application deadline`, {timeout: 5000}, async t => {
    const arrived = deferred(), bodyStarted = deferred();
    const server = createServer((request, response) => {
      if (phase === 'body') {
        response.writeHead(200, {'Content-Type': 'application/json'});
        response.write('{"accessExpiresAt":');
      }
      arrived.resolve();
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
    const page = browser({respond: async (action, options) => {
      const response = await fetch(`http://127.0.0.1:${server.address().port}/${action}`, options);
      bodyStarted.resolve();
      return response;
    }});
    const refresh = page.context.refresh();
    await arrived.promise;
    if (phase === 'body') await bodyStarted.promise;
    page.clock.fire(10000);
    await refresh;
    assert.equal(page.storage.get(blockedKey), '1');
    await page.context.logout();
    assert.deepEqual(page.calls, ['refresh'], 'no retry of an uncertain refresh after cancellation');
  });
}

const invalidAccess = () => Response.json({error: {code: 'invalid_token'}}, {status: 401});

for (const action of ['logout', 'logout-all']) {
  test(`review: ${action} recovers a rejected access hint once inside the same lock`, async () => {
    let logoutAttempts = 0, acquisitions = 0;
    const delegate = serializedLocks();
    const locks = {request(...args) { acquisitions++; return delegate.request(...args); }};
    const storage = currentStorage();
    const page = browser({storage, locks, respond: requestAction => {
      if (requestAction === 'refresh') {
        assert(!storage.has(expiryKey), 'server rejection invalidates the stale hint before rotation');
        assert.equal(storage.get(blockedKey), '1', 'persist the replay fence before submission');
        return tokens();
      }
      assert.equal(requestAction, action);
      return ++logoutAttempts === 1 ? invalidAccess() : new Response(null, {status: 204});
    }});
    assert.equal((await page.context.logout(action))?.status, 204);
    assert.equal(acquisitions, 1, 'recovery must not recursively acquire the exclusive lock');
    assert.deepEqual(page.calls, [action, 'refresh', action]);
    assert(!storage.has(expiryKey));
    assert.equal(storage.get(blockedKey), '1');
    await page.context.logout(action);
    await page.context.refresh();
    assert.deepEqual(page.calls, [action, 'refresh', action], 'a completed logout cannot restart rotation');
  });

  test(`${action}: a prior replay fence survives a known invalid-access response`, async () => {
    const storage = currentStorage();
    storage.set(blockedKey, '1');
    const page = browser({storage, respond: invalidAccess});
    assert.equal((await page.context.logout(action))?.status, 401);
    assert(!storage.has(expiryKey), 'do not keep trusting a rejected access hint');
    assert.equal(storage.get(blockedKey), '1');
    await page.context.logout(action);
    await page.context.refresh();
    assert.deepEqual(page.calls, [action], 'access rejection cannot authorize replay of an uncertain refresh');
  });

  test(`${action}: repeated invalid access after recovery cannot rotate a second time`, async () => {
    const page = browser({storage: currentStorage(), respond: requestAction =>
      requestAction === 'refresh' ? tokens() : invalidAccess()});
    assert.equal((await page.context.logout(action))?.status, 401);
    assert.deepEqual(page.calls, [action, 'refresh', action]);
    assert(!page.storage.has(expiryKey));
    assert.equal(page.storage.get(blockedKey), '1');
    await page.context.logout(action);
    await page.context.refresh();
    assert.deepEqual(page.calls, [action, 'refresh', action]);
  });

  test(`${action}: rotation before the first logout consumes the entire recovery budget`, async () => {
    const page = browser({respond: requestAction => requestAction === 'refresh' ? tokens() : invalidAccess()});
    assert.equal((await page.context.logout(action))?.status, 401);
    await page.context.logout(action);
    await page.context.refresh();
    assert.deepEqual(page.calls, ['refresh', action]);
    assert(!page.storage.has(expiryKey));
  });
}

for (const failure of ['network', 'unknown-outcome', 'replay', 'malformed-success']) {
  test(`recovery refresh ${failure} is never resubmitted or followed by a second logout`, async () => {
    const page = browser({storage: currentStorage(), respond: action => {
      if (action !== 'refresh') return invalidAccess();
      if (failure === 'network') throw new Error('refresh response lost');
      if (failure === 'unknown-outcome') return Response.json({error: {code: 'operation_outcome_unknown'}}, {status: 503});
      if (failure === 'replay') return Response.json({error: {code: 'refresh_replay'}}, {status: 401});
      return Response.json({});
    }});
    assert.equal(await page.context.logout(), null);
    assert.equal(page.storage.get(blockedKey), '1');
    await page.context.logout();
    await page.context.refresh();
    assert.deepEqual(page.calls, ['logout', 'refresh']);
  });
}

for (const [status, body] of [
  [401, '{"error":{"code":"refresh_replay"}}'],
  [401, '{"error":{"code":"operation_outcome_unknown"}}'],
  [401, '{"error":{"code":"invalid_credentials"}}'],
  [401, '{"error":{"code":["invalid_token"]}}'],
  [401, 'not JSON'],
  [401, 'null'],
  [403, '{"error":{"code":"invalid_token"}}'],
  [500, '{"error":{"code":"invalid_token"}}'],
  [503, '{"error":{"code":"operation_outcome_unknown"}}'],
]) {
  test(`logout cannot infer safe recovery from ${status} ${body}`, async () => {
    const page = browser({storage: currentStorage(), respond: () => new Response(body, {status})});
    assert.equal((await page.context.logout())?.status, status);
    await page.context.refresh();
    assert.deepEqual(page.calls, ['logout']);
    assert.equal(page.storage.get(blockedKey), '1');
  });
}

test('recovery holds the lock through both logout responses before a queued tab refresh', async () => {
  const storage = currentStorage(), locks = serializedLocks(), rejected = deferred();
  let attempts = 0;
  const first = browser({storage, locks, respond: action => {
    if (action === 'refresh') return tokens();
    return ++attempts === 1 ? rejected.promise : new Response(null, {status: 204});
  }});
  const second = browser({storage, locks});
  const logout = first.context.logout();
  await nextTurn();
  const waiting = second.context.refresh();
  await nextTurn();
  try { assert.deepEqual(second.calls, []); }
  finally { rejected.resolve(invalidAccess()); }
  assert.equal((await logout)?.status, 204);
  await waiting;
  assert.deepEqual(first.calls, ['logout', 'refresh', 'logout']);
  assert.deepEqual(second.calls, []);
});

test('unreadable 401 body is uncertain, not permission for recovery', async () => {
  let reads = 0;
  const page = browser({storage: currentStorage(), respond: (action, options) => ({
    ok: false, status: 401,
    text() { reads++; return waitForAbort(options.signal); },
  })});
  const logout = page.context.logout();
  await nextTurn();
  page.clock.fire(10000);
  assert.equal(await logout, null);
  assert.equal(reads, 1);
  assert.equal(page.storage.get(blockedKey), '1');
  await page.context.refresh();
  assert.deepEqual(page.calls, ['logout']);
});

test('lost recovery logout response keeps the new refresh fenced', async () => {
  let attempts = 0;
  const page = browser({storage: currentStorage(), respond: action => {
    if (action === 'refresh') return tokens();
    if (++attempts === 1) return invalidAccess();
    if (attempts === 2) throw new Error('logout response lost');
    return new Response(null, {status: 204});
  }});
  assert.equal(await page.context.logout(), null);
  assert.equal(page.storage.get(blockedKey), '1');
  await page.context.refresh();
  assert.deepEqual(page.calls, ['logout', 'refresh', 'logout']);
  assert.equal((await page.context.logout())?.status, 204, 'explicit retry may still revoke with live access');
  assert.deepEqual(page.calls, ['logout', 'refresh', 'logout', 'logout']);
});
