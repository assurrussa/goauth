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
introspected Fiber route, PostgreSQL RBAC, logout, password reset, and cleanup.
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
make integration-up
make release-candidate-readiness
make integration-down
```

After a new tag is published, run:

```sh
make externalconsumer-published VERSION=v0.4.0
make release-readiness VERSION=v0.4.0
```

The published probe creates a temporary module without a local replacement,
builds a Runtime, mounts Fiber, initializes optional OIDC/Redis and RBAC, and
runs the example test. A local replace proves only checkout compatibility.
Confirm the public release resolves without private module tokens or
`GOPRIVATE`/`GONOSUMDB` settings. The retained v0.1 source currently brings
private modules into the repository graph, and CI requires a private token;
the credential-free gate is therefore blocked. `v0.4.0` remains unpublished
until its tag and published probe actually exist and pass.

## Evidence boundary

Keep local verification, tag publication, consumer adoption, and production
deployment as distinct claims. Record the exact version/commit for every gate;
manual production smoke remains outstanding until it is actually performed.
