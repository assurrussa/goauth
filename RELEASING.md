# Releasing goauth

This module is published as `github.com/assurrussa/goauth`.

## Current Baseline

- Current verified release baseline: `v0.1.6`.
- Next maintenance candidate: `v0.1.7`. It aligns `gonotify` to `v0.3.11`
  and both Outbox core and PostgreSQL backend modules to `v0.12.0`. Runtime
  behavior, migrations, and the supported package list do not change.
- The separate `v0.2` release line remains untouched. Because `v0.2.0` is
  already published, maintenance-line consumers must request exact `v0.1.7`;
  `@latest` continues to select `v0.2.0`.
- Keep module path unchanged: `module github.com/assurrussa/goauth`.
- Consumers should depend on published semver tags, not local `replace`
  directives, outside explicit sibling-development checks.

## Current consumer state

The post-split baseline uses the published module in known workspace consumers:

- `backend/go.mod` requires `github.com/assurrussa/goauth v0.1.6`.
- `backend/go.mod` has no local `replace` for `github.com/assurrussa/goauth`.
- `goadmin/go.mod` requires `github.com/assurrussa/goauth v0.1.6`.
- `goadmin/go.mod` has no local `replace` for `github.com/assurrussa/goauth`.

Before claiming a baseline is published-consumer ready, verify that it resolves
from a clean module:

The current consumer verification commands remain
`go list -m -json github.com/assurrussa/goauth@v0.1.6` and
`go get github.com/assurrussa/goauth@v0.1.6` until the dependent modules move.

```sh
go list -m -json github.com/assurrussa/goauth@v0.1.6
go get github.com/assurrussa/goauth@v0.1.6
```

After publishing the candidate tag, run the same clean checks against
`github.com/assurrussa/goauth@v0.1.7` before updating dependent modules.

For local work, use `GOAUTH_LOCAL_PATH` only for explicit sibling-development checks, not as a required module-level replace.

## Supported External Surface

`reference/externalconsumer` is the source of truth for supported packages. It
contains the compile-checked import manifest and the machine-readable
`SupportedPackages` list used by `cmd/externalconsumerprobe`.

Do not grow `HostSupportPackages` silently. Prefer moving host-facing behavior
behind `integration/*`, `core`, `shared`, `migrations`, or other intentional
stable packages.

## Full Run

From the repository root:

```sh
make
```

This runs the mutating preparation phase and then verification:

- `go mod tidy`
- `go generate ./...`
- `go fmt`, `gofumpt`, and `gci`
- `golangci-lint run --fix`
- `go mod tidy -diff`
- non-mutating `gofumpt` and `gci` checks
- `go vet ./...`
- `golangci-lint run`
- one `go test -race -cover -count=1 ./...` pass
- local external-consumer probe

Repeated race stress and HTML coverage artifacts are explicit diagnostics:
`make test-race` and `make cover-html`. Do not stack them onto a successful
`make check` unless the release or investigation specifically requires them.

For a non-mutating verification pass after preparation, run:

```sh
make check
```

## Release Readiness

Before tagging, run `make check` on the exact commit that will be released.
After publishing the tag, run the release-readiness gate; it repeats the local
checks and adds a clean temporary consumer that resolves the published version
through `cmd/externalconsumerprobe`.

For the current candidate after tagging:

```sh
make release-readiness VERSION=v0.1.7
```

## Host Consumer Validation

After publishing, host repos should remove local replaces and run their own
published-module gates. For a sibling `site` checkout, the expected post-split
gate is:

```sh
cd ../site
task platform:published-check GOAUTH_VERSION=v0.1.7 GOADMIN_VERSION=v0.4.0-alpha.14
```

## Release-visible behavior

- `v0.1.7` changes only dependency pins: `gonotify v0.3.11`, Outbox core
  `v0.12.0`, and Outbox PostgreSQL backend `v0.12.0`. The supported goauth
  package manifest is unchanged.

- `integration/roles.WithRolePresets` lets hosts seed idempotent canonical role
  policies alongside their permission definitions. Presets cannot override
  built-in slugs or reference permissions outside the merged seed catalog.

- `goauth/migrations` exposes public `DatabaseConfig` and `RunWithConfig` so
  clean consumers can run canonical auth/RBAC migrations without importing
  infrastructure packages.
- `authjwtservice.WithProfileProvisioner`,
  `localjwt.Options.ProfileProvisioner`, and `authcore.ProfileProvisioner`
  expose the host projection provisioning hook.
- Existing canonical subjects can create or restore host projections during successful Local JWT login before token issuance.

## Notes

- Do not add auth DDL or runtime compatibility fallbacks as part of a patch
  release unless the migration story is explicit.
- Keep host `users` and `administrations` tables as projections/memberships.
- `Subject.Kind` is routing metadata, not the admin security boundary.
- `cmd/externalconsumerprobe` is a release helper, not runtime API.
