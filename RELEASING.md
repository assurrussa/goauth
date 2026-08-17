# Releasing goauth

The module path is `github.com/assurrussa/goauth`.

## Version state

- Current published compatibility baseline: `v0.1.6`.
- Next release train: `v0.2.0-rc.1`, subsequent immutable RCs as needed, then
  `v0.2.0` on the exact commit of the last RC that passed every consumer gate.
- Never move or replace an existing tag. Never publish a committed local
  `replace` directive.
- Publication is not production deployment.

## Breaking migration

v0.2 installs a clean baseline schema. `postgres.Migrate` detects a v0.1 auth
schema and returns `postgres.ErrLegacySchemaRequiresReset` without deleting
data. Only isolated development and test databases may call:

```go
postgres.Down(ctx, db, postgres.ResetConfirmation)
```

There is no automatic v0.1 data conversion. A production-data migration would
require a separately reviewed migration product and is outside this release.

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

## RC sequence

1. Create the RC tag from a clean commit and push it.
2. Run the published-module probe:

   ```sh
   make release-readiness VERSION=v0.2.0-rc.1
   ```

3. Test consumer branches in dependency order: `goadmin`, `site/backend`,
   OIDC demos, `platformctl` generated host, `vaultkey`, `gocms`, `gowebhooks`,
   and the second host.
4. Fix defects in a new commit and publish a new RC; do not move the prior RC.
5. Put `v0.2.0` on the exact fully verified RC commit, then publish compatible
   `goadmin` and `platformctl` versions and pin applications to stable tags.

## Consumer evidence

Each consumer must record:

- the resolved `goauth` version and absence of a committed `replace`;
- its canonical format, lint, test, migration, and PostgreSQL gates;
- its realm membership and permission mapping checks;
- explicit development/test schema reset evidence where applicable;
- any remaining manual or production smoke separately from local verification.

After stable adoption, update the compatibility matrix and shared platform
wiki. Do not claim a live deployment from tags or local gates alone.
