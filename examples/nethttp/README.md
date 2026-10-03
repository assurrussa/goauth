# Standard net/http host example

One `postgres.Runtime` serves browser sessions, a bearer-only JSON API, the
native encrypted notification worker, and hourly retention cleanup. This is a
runnable development host, not a deployment template. It uses Go 1.27 and the
repository's existing dependencies.

For production, supply a host-owned sender following the
[notification delivery contract](../../docs/notification-delivery.md), including
the optional confidential NotifyHub integration. This example keeps its
localhost-only SMTP catcher and does not add a GoNotify dependency.

From the repository root:

```sh
docker compose -f examples/nethttp/compose.yaml up -d --wait
# Generate distinct random keys once. Protect and retain this file between runs.
(umask 077; GENERATE_KEYS=1 go run ./examples/nethttp > /tmp/goauth-example-keys.env)
. /tmp/goauth-example-keys.env
export DATABASE_URL='postgres://goauth:local-development-only@127.0.0.1:5432/goauth?sslmode=disable'
export PUBLIC_ORIGIN='http://localhost:8080'
export LOCALHOST_DEV=1
go run ./examples/nethttp
```

Use the repository's `.go-cache` environment when running these commands in a
sandbox (`GOCACHE`, `GOMODCACHE`, and `GOPATH`, as documented in the root
`AGENTS.md`). Key generation intentionally writes secrets to the redirected
private file; the running server never prints keys, notification contents,
connection strings, passwords, codes, or tokens. The key file is outside the
repository; do not commit it. Generating new keys against an existing database
invalidates old tokens and prevents old queued notifications from decrypting.

Open <http://localhost:8080> and <http://localhost:8025> (Mailpit). Sign up,
click **Send verification**, read the verification code in Mailpit, verify,
then log in again for a full user
session. Protected account access requires verified email. The UI supports
refresh, logout, logout all sessions, requesting/resetting passwords, changing
a password, and requesting/confirming an email change. A reset link puts its
token in the URL fragment; the page moves it into the form and removes the
fragment. Password reset/change and email confirmation changes revoke sessions.
Email change requires the current local password and a full user session.
Confirmation codes arrive at the new address; the completed-change notification
goes to the previous address without any credential. Re-login after those
changes. All browser mutations use POST and the host's CSRF policy.

Browser tokens live in `__Host-SSID` and `__Host-UUIDR`, `HttpOnly`, `SameSite=Lax` cookies scoped to
`/` without a Domain attribute. Cookies are `Secure` by default. `LOCALHOST_DEV=1` explicitly
permits HTTP and distinct `goauth_dev_SSID`/`goauth_dev_UUIDR` cookie names only with a localhost origin. Normal mode
requires an HTTPS origin plus `TLS_CERT` and `TLS_KEY`; the default listener is
`127.0.0.1:8443`. Override `LISTEN_ADDR` as needed. The SMTP sender is deliberately
restricted to a local catcher (`SMTP_ADDR`, default `127.0.0.1:1025`) and has
connection, send, and cancellation deadlines. The development services bind
only to loopback. Auto-migrations run at startup in this example.

The browser bridge rejects incoming Authorization headers and duplicate credential cookies, reads its own
cookies, and hides tokens from JSON responses. It requires a non-simple
`X-Goauth-CSRF: 1` header on every mutation and uses standard
`http.CrossOriginProtection`; no cross-origin CORS permission is granted. The
browser code serializes all POSTs with one Web Lock, including login, registration,
refresh, logout and local cookie removal. A delayed login response completes
before a queued logout. Browsers without Web Locks cannot use these mutations;
there is no unsynchronized fallback. Use a supported browser, or its own site-data
controls for local cleanup. Fetch (including response body reads) has a 10-second
AbortController deadline; queued lock acquisition has a separate 15-second
cancellation deadline. A queued timeout sends no request and does not steal an
active lock. Browser suspension may delay timers: these are not server deadlines.
Request bodies, headers, server operations and SMTP sends are bounded.
Worker failure stops the server; SIGINT/SIGTERM drains HTTP, cancels and joins
workers, then closes the owned database connection.

The `/api/` routes never read cookies or set them. Supply bearer access tokens
and explicit JSON refresh tokens. All operations are POST except protected
`GET /api/me`:

```sh
curl -sS http://localhost:8080/api/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"api@example.test","password":"Unique-API-Passphrase-1"}'
# Paste the access token from the JSON response:
curl -sS http://localhost:8080/api/email-send \
  -H 'Authorization: Bearer <accessToken>' -H 'Content-Type: application/json' -d '{}'
# Then use the code delivered to Mailpit:
curl -sS http://localhost:8080/api/email-verify \
  -H 'Authorization: Bearer <accessToken>' -H 'Content-Type: application/json' \
  -d '{"code":"<code>"}'
curl -sS http://localhost:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"scheme":"email","identifier":"api@example.test","password":"Unique-API-Passphrase-1","realm":"user"}'
curl -sS http://localhost:8080/api/me -H 'Authorization: Bearer <newAccessToken>'
curl -sS http://localhost:8080/api/refresh -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'
```

Other API paths and JSON bodies:

- `/api/email-send`: `{}` with bearer token; confirmation sessions allowed.
- `/api/logout`: `{}` with bearer token; confirmation sessions allowed.
- `/api/logout-all`: `{}` with a full user bearer token.
- `/api/reset-request`: `{"email":"api@example.test"}`.
- `/api/reset`: `{"token":"<resetToken>","newPassword":"<newPassword>"}`.
- `/api/password`: `{"currentPassword":"<current>","newPassword":"<new>"}` with bearer token.
- `/api/email-change`: `{"email":"new@example.test","currentPassword":"<current>"}` with a full user bearer token.
- `/api/email-confirm`: `{"code":"<code>"}` with bearer token.

Realm middleware checks persisted session state by default, so revoked sessions
fail immediately. `nethttp.RealmMiddlewareOptions.OfflineJWT` is an explicit
opt-out accepting stale authorization until JWT expiry; this host does not use
it. Auth context is read with `nethttp.AuthContext(request.Context())`.
`operation_outcome_unknown` returns 503. Refresh is single-use: do not retry the
same refresh token after an uncertain network/commit result; require login to
recover. The UI does not blindly retry failed or uncertain mutations.

Logout uses a still-valid access cookie immediately, even in the last 30 seconds
or after a previous refresh/logout failure. A refresh-only block does not suppress
an explicit logout retry. If access has expired, logout may rotate once under the
same lock, but never reuses a refresh whose outcome is uncertain. Local expiry
metadata is only a scheduling hint, never authorization.

If that hint is still current but the server returns exactly HTTP 401 with
`error.code: "invalid_token"`, logout discards the hint and may recover once:
`logout -> refresh -> logout` (the same applies to logout-all). This remains in
one Web Lock. Recovery is allowed only when no earlier refresh block exists and
this logout operation has not already rotated. The parsed error code comes from
the same bounded body read, not from UI text. Other errors and unreadable responses
do not authorize recovery. A second rejection or failed/uncertain refresh stops
recovery and preserves the replay block; it never loops through token rotation.

**Forget this browser** calls the browser-only `POST /browser/forget-session`
with `{}` and the same CSRF/origin protection. It clears the host's cookies even
when they are expired/malformed or the auth backend is unavailable. It does not
read or mutate canonical sessions and deliberately reports
`{"browserCredentialsCleared":true,"serverSessionsRevoked":false}`. It is not
logout-all, and other devices or copied credentials remain valid. There is no
`/api/forget-session`. A network failure cannot confirm that the browser received
the cookie deletion; use browser site-data controls when the host is unreachable.

Recovery and regression details: [PR #10 review fixes](../../docs/pr10-review-fixes.md).

```sh
go test -race ./nethttp ./examples/nethttp
docker compose -f examples/nethttp/compose.yaml down
```

The tests prove default revocation enforcement, confirmation/realm boundaries,
wire format and safe errors, body bounds, browser CSRF/cookie settings, mutating
GET rejection, and API cookie separation. A live PostgreSQL/SMTP/browser smoke
is a separate validation from these in-memory HTTP tests.

## Browser smoke evidence (2026-09-28)

A real headed Playwright browser ran against this example's isolated PostgreSQL
and local SMTP catcher. Verified: signup (201), challenge delivery (202), email
verification (200), login and protected account access (200), refresh (200),
logout (204), and logout all sessions (204). Replaying old session cookies after
logout or logout all returned 401 immediately. Concurrent refresh clicks in two
browser tabs completed; the captured current-tab request returned 200. A global
exact request count across both tabs was not retained.

Missing browser CSRF headers returned 403; mutating GET returned 405. API access
using browser cookies alone returned 401, while explicit bearer access returned
200. Browser JSON hid tokens, and cookies were inaccessible to page JavaScript.
The live smoke used explicit localhost development mode; secure default cookie
flags are covered by host HTTP tests. Email-change and password-reset requests
returned 202 and their notifications arrived in the SMTP catcher.

Password-change/reset submission and email-change confirmation were not browser
verified. Automatic approval review required user hand-off for password changes,
even for the disposable local account; no workaround was attempted. Their
implementation and automated checks must be assessed separately from this
browser evidence.

The example server exited through graceful shutdown, the browser session was
closed, and the isolated containers and network were removed. The development
database volume was retained.
