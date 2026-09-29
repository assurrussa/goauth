# PR #10 review corrections

Reviewed base: `408d4ea6a55e813c396d649a6eda7a116159aac5`.
This follow-up corrects the logout/coordinator, test-fixture and example-documentation
findings. It also closes the related client-side wait and pending-login gaps.
Earlier results in `reauth-email-logout.md` describe the original implementation,
not independent evidence for this follow-up.

## Behavior

Logout tries a live access cookie without proactive refresh, including the last
30 seconds of its lifetime. A refresh-only block no longer prevents a subsequent
explicit logout attempt. An expired access credential may be refreshed once under
the same lock, but failed/uncertain refresh is never automatically replayed.
A client expiry timestamp is only a scheduling hint; authorization stays on the
server. Failed/uncertain revocation is never represented as successful logout.

All browser POST operations, including login/register and cookie removal, use
one Web Lock. Earlier login responses finish before queued logout, including
response-body consumption and cookie processing. A genuinely new login after
logout is allowed. Browsers without Web Locks have no unsynchronized mutation
fallback. This coordinates participating tabs, not arbitrary callers or old
versions of the example still open in another tab.

Fetch and response body reads share a 10-second AbortController deadline. Queued
lock acquisition has a separate 15-second abort deadline; it is removed when the
lock is acquired. Cancellation never steals an active lock, and a timed-out
queued operation cannot execute later. Browser suspension can delay timers.
Aborting network work cannot prove that the server did not commit it.

The explicit browser-only `POST /browser/forget-session` recovery action clears
host cookies without validating or mutating auth state. It retains CSRF-header
and CrossOriginProtection checks and reports `serverSessionsRevoked: false`.
It is deliberately not logout or logout-all; other credentials remain valid.
The browser UI serializes it with credential issuance. If the host is unreachable,
use browser site-data controls; the client cannot clear HttpOnly cookies itself.

## Tests and documentation

The unchanged-email denial test now obtains a full session by trusted provisioning
followed by normal login and supplies the current password. It still requires
422 `email_change_same_value`; it was not weakened to accept a scope denial.
A new HTTP lifecycle test exercises middleware plus the real testkit Runtime,
wrong/missing passwords, pending state, both notification destinations and session
revocation. Recovery tests check CSRF, method/API separation, cookie scope, no
Runtime dependency and the explicit absence of canonical session revocation.

The README now documents the actual email-change JSON and recovery behavior.
The real HTTPS/PostgreSQL browser script additionally exercises a known 503 logout
retry, queued logout behind a delayed genuine login response, and local cookie
removal with the canonical session demonstrably still valid. This is acceptance
code, not a claim that Chromium/PostgreSQL ran in this session.

## Verification of this follow-up

- The four archived review reproductions failed on the unchanged base `app.js`.
  Its Git blob matched `379a6f9f95efc7ac672eea0f9d59e5905c97164e`.
- All 28 updated Node tests passed on Node 22.16.0. These include deterministic
  timers/FIFO lock fixtures and two real loopback HTTP/native-fetch cancellation
  tests covering stalled headers and response bodies. They are not Chromium tests.
- JavaScript syntax and Go formatting/parser checks passed for the changed source.
  Parsing Go is not typechecking, lint or execution of Go tests.
- Downloading the declared Go 1.27.1 toolchain failed resolving proxy.golang.org;
  the installed compiler is Go 1.23.2. No versions or dependencies were downgraded.
  Go unit/race/integration/lint, Chromium acceptance and the complete candidate gate
  are unverified for this follow-up and must run before merge.

On the declared toolchain and documented disposable services, run
`make release-candidate-readiness`. No production deployment, schema migration,
public tag, visibility change or historical evidence upgrade is included.
