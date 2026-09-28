# Releasing goauth

The module path is `github.com/assurrussa/goauth`.

## Version state

- Current release version: `v0.4.0`; previous stable release: `v0.3.0`.
- `v0.2.0-rc.1` and `v0.2.0` resolve to the same fully verified commit. Both
  tags are immutable; future fixes require a new semver tag.
- The frozen v0.1 compatibility line ends at `v0.1.7`.
- The v0.1 use cases remain compile-checked in `internal/legacy`. External
  consumers cannot import them; immutable v0.1 tags preserve the old API.
- Never move or replace an existing tag. Never publish a committed local
  `replace` directive.
- Publication is not production deployment.

## Breaking migration

v0.2 installs a clean baseline schema. `postgres.Migrate` detects a v0.1 auth
schema and returns `postgres.ErrLegacySchemaRequiresReset` without deleting
data. Only isolated development and test databases may call:

```go
postgres.Down(ctx, db, postgres.ConfirmResetAuthState)
```

There is no automatic v0.1 data conversion. A production-data migration would
require a separately reviewed migration product and is outside this release.
The reset is transactional and refuses to drop `auth_subjects` while host
projection foreign keys still depend on it; each consumer reset must remove its
own auth projections first.

The v0.4 notification migration advances the schema version from 2 to 3 while
preserving v0.2 auth rows. An older binary that verifies version 2 will reject
the upgraded database, even if its `AutoMigrate` option is enabled. Roll back
the application only to a binary that accepts version 3; otherwise restore a
pre-migration database snapshot after accounting for writes made since it was
taken. Do not run `Down` against production data as a rollback mechanism.

## Local release gate

Run preparation once, inspect its diff, then run the canonical non-mutating
candidate gate once:

```sh
make prepare
make integration-up
make release-candidate-readiness
make integration-down
```

`make release-candidate-readiness` includes `make check`, PostgreSQL and Redis
integration, reachable vulnerability analysis, and aggregate coverage.
`make check` covers tidy diff, formatting, vet, lint, a single race/coverage
test pass, the critical-package coverage floor, the exact public API manifest,
and the runnable local clean-consumer probe. `make integration-up` and
`make integration-down` manage the services in `compose.integration.yml`.

## Public dependency prerequisite

The restored v0.1 tree brings private modules back into the repository's
module graph and CI needs `PRIVATE_GO_MODULES_TOKEN`. This blocks a
credential-free public build even though the supported v0.2 imports do not
depend on those old packages. Resolve and verify the source/dependency
distribution boundary before changing repository visibility or tagging v0.4.

After that blocker is resolved, enable and verify GitHub private vulnerability
reporting before announcing or tagging the release so
the channel in [SECURITY.md](SECURITY.md) is usable. The supported import graph
and CI must resolve without `GOPRIVATE`, `GONOSUMDB`, or a private Go module
token. Public pull requests run the same
CI job without repository secrets. A local probe uses a temporary `replace`
and proves checkout compatibility only; the public distribution claim requires
a clean published consumer after repository visibility and tagging.

## Public v0.4 release sequence

1. Resolve the private dependency blocker, verify the candidate commit, make
   repository visibility public, then enable and verify private vulnerability
   reporting. Check that all dependencies
   resolve without private credentials.
2. Create and push a new `v0.4.0` tag from that commit. Do not rewrite an
   existing tag.
3. Run the published-module gate:

   ```sh
   make release-readiness VERSION=v0.4.0
   ```

4. Test consumers in dependency order and record their own schema, realm,
   permission, and application gates. Keep manual production smoke separate
   from local checks. Fix defects in a new commit and tag; never move a tag.

## Consumer evidence

Each consumer must record:

- the resolved `goauth` version and absence of a committed `replace`;
- its canonical format, lint, test, migration, and PostgreSQL gates;
- its realm membership and permission mapping checks;
- explicit development/test schema reset evidence where applicable;
- any remaining manual or production smoke separately from local verification.

The historical v0.2 release train is recorded in
[docs/compatibility.md](docs/compatibility.md). It does not prove v0.4
compatibility. Keep that matrix and the shared platform wiki current after
stable adoption. Do not claim a live deployment from tags or local gates alone.
