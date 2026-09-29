# Releasing goauth

The module path is `github.com/assurrussa/goauth`.
Read [docs/public-release-plan.md](docs/public-release-plan.md) for the owner,
acceptance criteria and sequence of the first public preview.

## Version state

Use repository tags/release notes for existing versions and select the target
explicitly with `VERSION=<tag>`. There is no implicit latest/default version.
During preparation on 2026-09-28, `v0.4.1` pointed to `070b1f3`; that observation
alone is not evidence of public resolution or completed release checks.
The current unpublished candidate is `v0.5.0`.

Never move or replace a tag, publish a committed local `replace`, or describe a
private tag as a verified public release. The frozen v0.1 compatibility line
ends at `v0.1.7`; its implementation is absent from the current source tree.
Publication, independent review, consumer adoption and deployment are separate
claims. Fix a failed published candidate in a new commit and tag.

## v0.5 migration

The v0.5 code changes Runtime/store contracts and HTTP authorization defaults.
It preserves the version-3 database and existing rows; no `Down` is required.
Read [docs/v0.5-migration.md](docs/v0.5-migration.md), including exact external
issuer keys and custom transaction wiring. Candidate verification does not
publish a tag, change visibility, or establish production adoption.

## Breaking v0.1 to v0.2 migration

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

## Candidate gate (before tagging)

Use the project's declared Go toolchain. Run `make prepare` once, inspect and
commit any resulting changes, then run the non-mutating candidate gate against
that exact SHA with disposable PostgreSQL and Redis services:

Select an installed Playwright module and Chromium executable as described in
[release verification](docs/release-verification.md); the candidate gate
requires those tools and does not install them automatically.

```sh
make integration-up
make release-candidate-readiness
make integration-down
```

Always tear down the disposable services even if verification fails.
The candidate gate includes format/tidy/vet/lint, one race/coverage unit pass,
public API checks, local consumer, PostgreSQL/Redis integration and real
PostgreSQL consumer, reachable vulnerability analysis, and aggregate coverage.
`make check` also runs the network-free source-guard regression tests.
The candidate gate additionally exercises real PostgreSQL dump/restore and
Chromium/HTTPS browser acceptance.

The `CI` workflow supports manual dispatch for a candidate branch as well as
pushes/PRs. Record its SHA and outcome. A job that cannot acquire a runner is
not a successful test run; resolve account/runner availability separately.
Do not lower security checks or change visibility merely to bypass CI failure.

## First public-release prerequisites

Before changing visibility, close release-blocking security findings and
review all history/refs that will become visible for secrets, internal data
and redistribution rights. A HEAD-only scan is insufficient. Record the scope
and outcome privately without publishing secrets. Changes of visibility or
history require the maintainer's explicit approval.

Immediately after opening visibility, enable and verify private vulnerability
reporting as described in [SECURITY.md](SECURITY.md), before announcing or
tagging the public release. Review branch/tag protection and support scope.

## Exact-tag publication gate

Create a **new unused tag** at the reviewed, candidate-tested commit only after
the prerequisites above. From a clean checkout at that tag, run:

```sh
make public-module-check VERSION=<tag>
```

`release-source-check` first checks that the tag exists locally, resolves to
HEAD, and the checkout has no staged, unstaged or untracked changes. It changes
no files or Git refs. `externalconsumer-published` then runs an executable
consumer against exactly that public version. No credentials, user Go
configuration, local module/build cache, workspace or direct-VCS fallback are
available to the child Go commands. The public checksum service stays enabled.
The selected module must still have the requested version and no replacement
after test dependencies resolve.

For the full candidate and publication gates on that same tag, with disposable
integration services running:

```sh
make release-readiness VERSION=<tag>
```

Alternatively, dispatch `Public module verification` with the existing tag.
It checks out `refs/tags/<version>`, disables persisted checkout credentials
and the setup-go cache, and runs `make public-module-check`. It fails while the
repository is private. It does not publish anything or alter settings.

The public gate deliberately requires access to `proxy.golang.org` and
`sum.golang.org`. Proxy propagation or network errors are not success; rerun
after resolving them rather than adding a private proxy, disabling checksums,
or reusing a developer cache. The installed Go executable, helper build and
OS trust store are trusted inputs; this is not a hostile-code sandbox.

Publish release notes/announce only after the gate passes. Include migrations,
support limitations and actual evidence, not a blanket production-ready claim.

## Consumer evidence

Each consumer records its resolved version and absence of local replacements,
its own format/lint/test/migration gates, realm membership and permission
checks, any explicit disposable-data resets, and unperformed/manual smoke
checks separately. The historical matrix in [docs/compatibility.md](docs/compatibility.md)
does not prove adoption of v0.5 or a newer release. Do not infer deployment from tags
or local tests alone.
