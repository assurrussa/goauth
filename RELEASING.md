# Releasing goauth

This module is published as `github.com/assurrussa/goauth`.

## Current Baseline

- Current verified release baseline: `v0.1.4`.
- Next additive candidate: `v0.1.5`, adding host-owned role presets through
  `integration/roles` without changing the supported package list.
- Keep module path unchanged: `module github.com/assurrussa/goauth`.
- Consumers should depend on published semver tags, not local `replace`
  directives, outside explicit sibling-development checks.

## Current consumer state

The post-split baseline uses the published module in known workspace consumers:

- `backend/go.mod` requires `github.com/assurrussa/goauth v0.1.4`.
- `backend/go.mod` has no local `replace` for `github.com/assurrussa/goauth`.
- `goadmin/go.mod` requires `github.com/assurrussa/goauth v0.1.4`.
- `goadmin/go.mod` has no local `replace` for `github.com/assurrussa/goauth`.

Before claiming a baseline is published-consumer ready, verify that it resolves
from a clean module:

Verification commands are `go list -m -json github.com/assurrussa/goauth@v0.1.4`
and `go get github.com/assurrussa/goauth@v0.1.4`.

```sh
go list -m -json github.com/assurrussa/goauth@v0.1.4
go get github.com/assurrussa/goauth@v0.1.4
```

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
- `go vet ./...`
- `golangci-lint run`
- `go test ./...`
- `go test -race -count=5 ./...`
- coverage HTML generation
- local external-consumer probe

For a non-mutating verification pass after preparation, run:

```sh
make check
```

## Release Readiness

Before tagging a new version:

```sh
make release-readiness VERSION=<tag>
```

This includes `make check` plus a clean temporary consumer resolving the
published version through `cmd/externalconsumerprobe`.

For the current baseline:

```sh
make release-readiness VERSION=v0.1.4
```

## Host Consumer Validation

After publishing, host repos should remove local replaces and run their own
published-module gates. For `/Users/amir/dev/projects/my/site`, the expected
post-split gate is:

```sh
cd /Users/amir/dev/projects/my/site
task platform:published-check GOAUTH_VERSION=v0.1.4 GOADMIN_VERSION=v0.2.3
```

## Release-visible behavior

- `integration/roles.WithRolePresets` lets hosts seed idempotent canonical role
  policies alongside their permission definitions. Presets cannot override
  built-in slugs or reference permissions outside the merged seed catalog.

- `goauth/migrations` exposes public `DatabaseConfig` and `RunWithConfig` so
  clean consumers can run canonical auth/RBAC migrations without importing
  infrastructure packages.
- `authjwtservice.WithProfileProvisioner`,
  `localjwt.Options.ProfileProvisioner`, and `authcore.ProfileProvisioner`
  expose the host projection provisioning hook.
- Existing canonical subjects can create or restore host projections during
  successful Local JWT login before token issuance.
- canonical subjects can create or restore host projections during successful Local JWT login.

## Notes

- Do not add auth DDL or runtime compatibility fallbacks as part of a patch
  release unless the migration story is explicit.
- Keep host `users` and `administrations` tables as projections/memberships.
- `Subject.Kind` is routing metadata, not the admin security boundary.
- `cmd/externalconsumerprobe` is a release helper, not runtime API.
