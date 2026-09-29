# Release verification

## Local gates

```sh
make prepare
make check
```

`make prepare` modifies files. Review and commit its diff before recording a
candidate SHA. `make check` is non-mutating and runs one canonical race/coverage
pass, static checks, public API tests, a local consumer and source-guard tests.
Use `make test-race` only for deliberate stress reruns and `make cover-html`
only when an HTML artifact is needed.

The security integration suite requires disposable PostgreSQL and Redis:

```sh
make integration-local
```

It checks migrations/upgrade/rollback, legacy-schema refusal, atomic refresh,
reset and challenge behavior, identifier uniqueness, SSO policy, revocation,
secret-at-rest assertions, notification delivery/retry and Redis concurrency.
It also executes the PostgreSQL consumer: Runtime assembly, notification
worker startup/shutdown, delivery/acknowledgement, email verification, login,
an introspected Fiber route, RBAC, logout, reset and cleanup. That path must
fail when `GOAUTH_TEST_POSTGRES_DSN` is absent or its database is unreachable.
Never run it against production data.

## Coverage and vulnerabilities

`make check` and `make integration` enforce at least 80% statement coverage for
the configured security-critical root, PostgreSQL, Redis, OIDC-provider and
RBAC packages. `make coverage-aggregate` merges their atomic profiles.
`make vulnerability-check` runs the pinned tool with `go tool govulncheck ./...`.
A finding needs remediation or reviewed reachability evidence, not a silent
waiver. Coverage alone does not prove the auth invariants.

## Candidate and local consumers

```sh
make externalconsumer-local
make externalconsumer-postgres-local
```

These use a local `replace` and may reuse the developer module cache. Both
force `GOWORK=off`; the PostgreSQL path deliberately receives the configured
disposable database. They prove checkout integration, not public availability.
For the combined candidate gate, start integration services, run
`make release-candidate-readiness`, then stop the services even on failure.

## Public, exact-version consumer

After publication, from a clean checkout of the chosen tag:

```sh
make public-module-check VERSION=<tag>
```

This requires an explicit version and verifies HEAD/clean-tree/tag agreement
before starting the published probe. `make release-readiness VERSION=<tag>`
also runs the candidate gate and therefore requires integration services.
The manual `Public module verification` workflow performs the same public
check for an existing tag; it cannot change visibility or create a release.

`make externalconsumer-published VERSION=<tag>` may be used as a lower-level
compatibility diagnostic from a different checkout, but does not prove that
that checkout matches the release tag.

Published mode creates fresh HOME, Go module/build caches and temporary state.
It sets `GOENV=off`, `GOWORK=off`, `GOAUTH=off`, uses only the public Go proxy
and checksum database, and disables direct VCS downloads. It does not inherit
private patterns, auth helpers, caller proxy credentials, database secrets,
user configuration or build flags. The helper itself is built from the trusted
checkout before these isolated child Go processes run.

The initial `go list -m -json module@version` and the selected-module check after
`go test` must both report the exact requested path/version and no replacement.
Aliases such as `latest` and branches cannot stand in for an exact version.
Published mode rejects local-path, shared-cache and PostgreSQL-integration
flags. Use local mode for the database probe.

A cold download gets a 10-minute per-command timeout through the Makefile;
`--timeout` controls each subprocess, not total runtime. On failure,
`--keep-workdir` preserves the consumer and fresh caches for inspection. It
does not relax isolation. The Go executable and system trust store remain
trusted; this is an environment-isolation check, not an OS security sandbox.

## Evidence boundary

Keep implementation, local verification, tag creation, anonymous publication,
independent security review, consumer adoption and production deployment as
separate facts. Record the exact SHA/version and commands for every gate.
File-scoped tests on another Go version, static review, an unavailable runner
or a failed network lookup must not be reported as a full passing gate.
