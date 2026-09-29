'use strict';
const output = document.querySelector('#result');
const expiryKey = 'goauth-access-expiry';
const blockedKey = 'goauth-refresh-blocked';
const requestTimeoutMS = 10000;
const lockWaitTimeoutMS = 15000;
const sessionIssuers = new Set(['register', 'login', 'refresh']);
const sessionInvalidators = new Set(['logout', 'logout-all', 'password', 'email-confirm', 'reset', 'forget-session']);

function accessCurrent(margin = 0) {
  // This is only a scheduling hint. The server always checks the credential.
  return Date.parse(localStorage.getItem(expiryKey) || '') > Date.now() + margin;
}

// Only call this while holding the session lock, except for read-only requests.
async function sendRequest(action, data = {}, method = 'POST') {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMS);
  try {
    const response = await fetch('/browser/' + action, {
      method, credentials: 'same-origin', signal: controller.signal,
      headers: {'Content-Type': 'application/json', 'X-Goauth-CSRF': '1'},
      ...(method === 'POST' ? {body: JSON.stringify(data)} : {}),
    });
    // Keep the same deadline through body consumption, not just response headers.
    const text = await response.text();
    controller.signal.throwIfAborted();
    let value;
    try { value = JSON.parse(text); } catch { value = {message: text}; }
    if (response.ok && sessionIssuers.has(action)) {
      if (!value || !Number.isFinite(Date.parse(value.accessExpiresAt)) ||
          Date.parse(value.accessExpiresAt) <= Date.now()) {
        throw new Error('Unusable session response');
      }
      localStorage.setItem(expiryKey, value.accessExpiresAt);
      localStorage.removeItem(blockedKey);
    }
    if (response.ok && sessionInvalidators.has(action)) {
      localStorage.removeItem(expiryKey);
      localStorage.setItem(blockedKey, '1');
    }
    output.textContent = response.status + '\n' + JSON.stringify(value, null, 2);
    return response;
  } catch (error) {
    if (sessionIssuers.has(action) || sessionInvalidators.has(action)) {
      // Cancellation cannot prove that the server rolled back. Retain expiry so
      // an explicit logout can still try a live access cookie; never replay refresh.
      localStorage.setItem(blockedKey, '1');
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function withSessionLock(operation) {
  if (!navigator.locks) {
    output.textContent = 'This browser requires Web Locks for session mutations. No request was sent.';
    return null;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), lockWaitTimeoutMS);
  let acquired = false;
  try {
    // Abort cancels only a queued acquisition. Never steal another tab's lock.
    return await navigator.locks.request('goauth-refresh', {signal: controller.signal}, async () => {
      acquired = true;
      clearTimeout(timer);
      return operation();
    });
  } catch {
    output.textContent = acquired
      ? 'Request failed or timed out; server outcome is not confirmed. Retry logout with live access, log in again, or use Forget this browser.'
      : 'Session lock unavailable or waiting timed out. No request was sent; try again.';
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function refreshLocked(margin = 30000) {
  if (localStorage.getItem(blockedKey)) {
    output.textContent = 'Refresh is blocked after logout or an uncertain outcome. Log in again or use Forget this browser.';
    return false;
  }
  if (accessCurrent(margin)) return true;
  // Persist before submission so a closed/crashed tab cannot invite blind replay.
  localStorage.setItem(blockedKey, '1');
  const response = await sendRequest('refresh');
  return response.ok && !localStorage.getItem(blockedKey);
}

async function refresh() {
  return withSessionLock(() => refreshLocked());
}

async function logout(action = 'logout') {
  if (!['logout', 'logout-all'].includes(action)) throw new Error('Invalid logout action');
  return withSessionLock(async () => {
    // A refresh-only block must not prevent explicit revocation using live access.
    // Unlike background refresh, logout has no 30-second proactive refresh margin.
    if (!accessCurrent() && !await refreshLocked(0)) {
      output.textContent = 'Server revocation is not confirmed. Refresh cannot be retried safely; log in again or use Forget this browser.';
      return null;
    }
    const response = await sendRequest(action);
    if (!response.ok) localStorage.setItem(blockedKey, '1');
    return response;
  });
}

// All POSTs share the same lock, including login/register and credential removal.
// Earlier login response bodies/Set-Cookie finish before a queued logout begins.
// A genuinely new login after logout is still allowed.
async function request(action, data = {}, method = 'POST') {
  if (method === 'POST') {
    if (action === 'logout' || action === 'logout-all') return logout(action);
    if (action === 'refresh') return refresh();
    return withSessionLock(() => sendRequest(action, data, method));
  }
  try { return await sendRequest(action, data, method); }
  catch {
    output.textContent = 'Read request failed or timed out.';
    return null;
  }
}

for (const id of ['reset-request', 'reset', 'password', 'email-change', 'email-confirm']) {
  document.getElementById(id).addEventListener('submit', async event => {
    event.preventDefault();
    try { await request(id, Object.fromEntries(new FormData(event.target))); }
    finally {
      for (const input of event.target.querySelectorAll('input[type="password"]')) input.value = '';
    }
  });
}
document.getElementById('auth').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const data = Object.fromEntries(new FormData(event.target));
    const action = event.submitter.value;
    await request(action, action === 'login'
      ? {scheme: 'email', identifier: data.email, password: data.password, realm: 'user'} : data);
  } finally { event.target.password.value = ''; }
});
document.getElementById('code').addEventListener('submit', async event => {
  event.preventDefault();
  await request('email-verify', Object.fromEntries(new FormData(event.target)));
});
document.getElementById('email-send').addEventListener('click', () => request('email-send'));
for (const id of ['logout', 'logout-all']) document.getElementById(id).addEventListener('click', () => logout(id));
document.getElementById('forget-session').addEventListener('click', () => request('forget-session'));
document.getElementById('refresh').addEventListener('click', refresh);
document.getElementById('me').addEventListener('click', async () => {
  if (accessCurrent() || await refresh()) await request('me', {}, 'GET');
});
if (location.hash.startsWith('#reset=')) {
  document.querySelector('#reset [name=token]').value = new URLSearchParams(location.hash.slice(1)).get('reset');
  history.replaceState(null, '', location.pathname);
}
