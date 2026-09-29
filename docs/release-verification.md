# Release verification

## Local gates

```sh
make prepare
make check
```

`make check` is non-mutating and runs one canonical race/coverage pass. Use
`make test-race` only for deliberate stress reruns and `make cover-html` only
when an HTML artifact is needed.

The security integration suite requires PostgreSQL and Redis. The local target
starts and stops those services:

```sh
make integration-local
```

The integration suite executes the v0.2 migration, Down/Up, v0.1 refusal,
atomic refresh/reset/challenge behavior, case-insensitive identifier uniqueness,
SSO policy, status revocation, secret-at-rest assertions, native notification
queue delivery and retry, and Redis GETDEL concurrency.
It also runs the PostgreSQL external consumer probe against
`GOAUTH_TEST_POSTGRES_DSN`. The probe constructs `postgres.NewRuntime`, starts
and stops `RunNotifications`, checks an email challenge was delivered and
acknowledged, verifies the code, then exercises authenticated login, an
current-session Fiber and net/http routes, PostgreSQL RBAC, logout, password reset, and cleanup.
It requires a reachable, disposable integration database and fails if the DSN
is missing or the database is down.

## Coverage and vulnerabilities

`make check` and `make integration` enforce at least 80% statement coverage for
the security-critical root, PostgreSQL, Redis, OIDC-provider, and RBAC packages.
After both gates, `make coverage-aggregate` merges their atomic profiles for
inspection. `make vulnerability-check` runs the version pinned in `go.mod` via
`go tool govulncheck ./...`. A finding must be upgraded away or documented with
reachability evidence before release; a database-only result is not silently
treated as clean.

## Clean consumers

```sh
make externalconsumer-local
```

`make check` includes only this database-free probe. To run the real PostgreSQL
consumer path alone, set `GOAUTH_TEST_POSTGRES_DSN` and run
`make externalconsumer-postgres-local`; the Makefile's default DSN targets the
database in `compose.integration.yml`.

For the full unpublished candidate gate, start the integration services:

```sh
# Select an installed Playwright module and Chromium executable; no auto-install.
export GOAUTH_BROWSER_PLAYWRIGHT_MODULE="$PLAYWRIGHT_MODULE"
export GOAUTH_BROWSER_CHROMIUM_EXECUTABLE="$CHROMIUM_EXECUTABLE"
make integration-up
make release-candidate-readiness
make integration-down
```

The candidate gate also runs `make backup-restore-check` with real pg_dump/
pg_restore in the disposable Compose project, and `make browser-acceptance`
with a real HTTPS browser, canonical PostgreSQL Runtime, managed encrypted queue,
full account lifecycle and exactly one refresh across two tabs after access expiry.
Node, the selected installed Playwright module and Chromium must be available.
An invoked gate fails when the engine is missing; it does not silently skip or
install dependencies. These profiles use their own temporary databases. The
browser proof is the public same-origin example; separate host suites cover the
site's split API, opaque admin and live ZITADEL composition.

After a new tag is published, run:

```sh
make externalconsumer-published VERSION=v0.5.0
make release-readiness VERSION=v0.5.0
```

The published probe creates a temporary module without a local replacement,
builds a Runtime, mounts net/http and Fiber, initializes optional OIDC/Redis and
RBAC, and exercises the real PostgreSQL lifecycle against
`GOAUTH_TEST_POSTGRES_DSN`. A local replace proves only checkout compatibility.
Confirm the public release resolves without private module tokens or
`GOPRIVATE`/`GONOSUMDB` settings. A release tag remains unpublished until its
tag and published probe actually exist and pass.

## Evidence boundary

Keep local verification, tag publication, consumer adoption, and production
deployment as distinct claims. Record the exact version/commit for every gate;
manual production smoke remains outstanding until it is actually performed.

## Browser evidence

Use the runnable [net/http example](../examples/nethttp/README.md) for browser
signup, email verification, login/protected access, refresh and logout. The
browser host also exposes password reset/change and email change. Verify CSRF
rejection and that `/api` never accepts cookies as bearer credentials. Keep
actual browser checks distinct from httptest and published-consumer evidence.
