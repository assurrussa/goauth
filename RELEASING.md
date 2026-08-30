# Releasing goauth

The module path is `github.com/assurrussa/goauth`.

## Version state

- Current release version: `v0.2.1`; previous stable baseline: `v0.2.0` at
  `cd8bb98`.
- `v0.2.0-rc.1` and `v0.2.0` resolve to the same fully verified commit. Both
  tags are immutable; future fixes require a new semver tag.
- The frozen v0.1 compatibility line ends at `v0.1.7`.
- `v0.2.1` aligns `gonotify` to `v0.3.11` and Outbox core/PostgreSQL to
  `v0.12.0` without changing the supported package manifest or v0.2 schema.
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

## Local release gate

Run preparation once, inspect its diff, then run the canonical non-mutating
gate once:

```sh
make prepare
make check
make integration
make vulnerability-check
```

`make check` covers tidy diff, formatting, vet, lint, a single race/coverage
test pass, the critical-package coverage floor, the exact public API manifest,
and the runnable local clean-consumer probe. `make integration` requires the
PostgreSQL and Redis test services described in `compose.integration.yml`.

## GitHub Actions prerequisite

The repository must define `PRIVATE_GO_MODULES_TOKEN` as an Actions repository
secret. Use a dedicated least-privilege token with read-only Contents access to
the private `github.com/assurrussa/*` modules required by `go.mod`; do not use a
deployment or package-publishing credential. GitHub does not pass repository
secrets to workflows opened from forks, so those pull requests cannot run the
private-module gates without a separately reviewed trust model.

## RC sequence for a future release train

1. Create the RC tag from a clean commit and push it.
2. Run the published-module probe:

   ```sh
   make release-readiness VERSION=<candidate-tag>
   ```

3. Test consumer branches in dependency order: `goadmin`, `site/backend`,
   OIDC demos, `platformctl` generated host, `vaultkey`, `gocms`, `gowebhooks`,
   and the second host.
4. Fix defects in a new commit and publish a new RC; do not move the prior RC.
5. Put the stable tag on the exact fully verified RC commit, then publish
   compatible `goadmin` and `platformctl` versions and pin applications to
   stable tags.

## Consumer evidence

Each consumer must record:

- the resolved `goauth` version and absence of a committed `replace`;
- its canonical format, lint, test, migration, and PostgreSQL gates;
- its realm membership and permission mapping checks;
- explicit development/test schema reset evidence where applicable;
- any remaining manual or production smoke separately from local verification.

The verified v0.2 release train is recorded in
[docs/compatibility.md](docs/compatibility.md). Keep that matrix and the shared
platform wiki current after stable adoption. Do not claim a live deployment
from tags or local gates alone.
