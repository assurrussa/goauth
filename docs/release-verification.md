# Release verification

## Local gates

```sh
make prepare
make check
```

`make check` is non-mutating and runs one canonical race/coverage pass. Use
`make test-race` only for deliberate stress reruns and `make cover-html` only
when an HTML artifact is needed.

The security integration suite requires PostgreSQL and Redis:

```sh
docker compose -f compose.integration.yml -p goauth-v02-integration up -d --wait
make integration
docker compose -f compose.integration.yml -p goauth-v02-integration down -v
```

The integration suite executes the v0.2 migration, Down/Up, v0.1 refusal,
atomic refresh/reset/challenge behavior, case-insensitive identifier uniqueness,
SSO policy, status revocation, secret-at-rest assertions, and Redis GETDEL
concurrency.

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
make externalconsumer-published VERSION=v0.2.1
make release-readiness VERSION=v0.2.1
```

The probe creates a temporary module without a committed replace for published
versions, builds a Runtime, mounts Fiber, initializes OIDC/Redis and RBAC, and
runs the example test. A local replace proves only sibling-development
compatibility.

## Evidence boundary

Keep local verification, tag publication, consumer adoption, and production
deployment as distinct claims. Record the exact version/commit for every gate;
manual production smoke remains outstanding until it is actually performed.
