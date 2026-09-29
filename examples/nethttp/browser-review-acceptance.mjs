import assert from 'node:assert/strict';

// Runs inside the existing real Chromium/HTTPS/PostgreSQL lifecycle. Only the
// first logout response is injected; retries reach the actual host and Runtime.
export async function reviewBrowserRecovery({context, page, second, origin, raw, call, email, password}) {
  let attempts = 0;
  await page.route('**/browser/logout', async route => {
    if (++attempts === 1) {
      await route.fulfill({status: 503, contentType: 'application/json',
        body: JSON.stringify({error: {code: 'authentication_unavailable'}})});
    } else await route.continue();
  });
  try {
    const before = (await raw('/fixture/stats')).data.submitted;
    assert.equal((await call('logout')).status, 503);
    assert.equal((await call('logout')).status, 204);
    assert.equal((await raw('/fixture/stats')).data.submitted, before, 'live-access logout must not depend on refresh');
  } finally { await page.unroute('**/browser/logout'); }

  // Delay a genuine login response. Observe the actual queued Web Lock rather
  // than assuming that a short sleep placed logout behind the login.
  let releaseLogin, loginArrived, routeError;
  const released = new Promise(resolve => { releaseLogin = resolve; });
  const arrived = new Promise(resolve => { loginArrived = resolve; });
  await page.route('**/browser/login', async route => {
    try {
      const response = await route.fetch({timeout: 5000});
      loginArrived();
      await released;
      await route.fulfill({response});
    } catch (error) {
      routeError = error;
      loginArrived();
      await route.abort().catch(() => {});
    }
  });
  const login = call('login', {scheme: 'email', identifier: email, password, realm: 'user'});
  // Bound fixture setup as well as the application's own network deadline.
  let setupTimer;
  const setupExpired = new Promise((_, reject) => {
    setupTimer = setTimeout(() => reject(new Error('Delayed login fixture did not arrive')), 5000);
  });
  // Observe rejections immediately, while preserving them for the assertions.
  login.catch(() => {});
  let logout;
  try {
    await Promise.race([arrived, setupExpired]);
    assert.ifError(routeError);
    logout = second.evaluate(async () => (await window.logout())?.status);
    logout.catch(() => {});
    await second.waitForFunction(async () => (await navigator.locks.query()).pending
      .some(lock => lock.name === 'goauth-refresh'), null, {timeout: 5000});
  } finally {
    clearTimeout(setupTimer);
    releaseLogin();
    await Promise.allSettled([login, logout]);
    await page.unroute('**/browser/login');
  }
  assert.ifError(routeError);
  assert.equal((await login).status, 200);
  assert.equal(await logout, 204);
  assert(!(await context.cookies(origin)).some(cookie => ['__Host-SSID', '__Host-UUIDR'].includes(cookie.name)));
  assert.equal((await call('me', {}, 'GET')).status, 401);

  assert.equal((await call('login', {scheme: 'email', identifier: email, password, realm: 'user'})).status, 200);
  const savedCookies = (await context.cookies(origin)).map(cookie => cookie.name + '=' + cookie.value).join('; ');
  await page.evaluate(() => {
    localStorage.setItem('goauth-refresh-blocked', '1');
    localStorage.removeItem('goauth-access-expiry');
  });
  assert.equal((await raw('/browser/forget-session', 'POST', {}, {Origin: origin})).status, 403);
  const forgotten = await call('forget-session');
  assert.equal(forgotten.status, 200);
  assert.deepEqual(forgotten.data, {browserCredentialsCleared: true, serverSessionsRevoked: false});
  assert(!(await context.cookies(origin)).some(cookie => ['__Host-SSID', '__Host-UUIDR'].includes(cookie.name)));
  assert.equal((await call('me', {}, 'GET')).status, 401);
  assert.equal((await raw('/browser/me', 'GET', undefined, {Cookie: savedCookies})).status, 200,
    'explicitly forgetting cookies must not be mistaken for server revocation');
}
