# Public Surface Guide

## Contract

The supported external import surface is the machine-readable manifest in
`reference/externalconsumer`.

The authoritative list is:

- `reference/externalconsumer/packages.go`
- `reference/externalconsumer/imports.go`

The compile and release checks are:

- `reference/externalconsumer/manifest_test.go`
- `public_surface_test.go`
- `cmd/externalconsumerprobe`

## Stable Surface Shape

Current stable public packages are grouped around:

- `core` and `shared` contracts;
- host wiring kits under `integration/adminsession`, `integration/localjwt`,
  `integration/oidc`, `integration/roles`, and `integration/storage`;
- canonical migrations through `migrations`;
- selected Local JWT/password/token services under `local/*`;
- selected OIDC and SSO packages;
- selected auth services;
- HTTP middleware/context helpers that are explicitly listed in the manifest.

`HostSupportPackages` is currently empty. Keep it empty unless an unavoidable
temporary compatibility package is needed and the migration path is documented.

## Adding A Public Package

When promoting a package to supported public API:

1. Confirm the package is a reusable contract or facade, not a host-specific
   implementation detail.
2. Prefer adding or extending an `integration/*` facade instead of exposing a
   deep implementation package.
3. Add the package to `StablePublicPackages` in
   `reference/externalconsumer/packages.go`.
4. Add a matching blank import to `reference/externalconsumer/imports.go`.
5. Add public symbol coverage to `public_surface_test.go` when consumers rely on
   exported constructors, options, types, or constants.
6. Run `make check`.
7. For release claims, run `make release-readiness VERSION=<tag>`.

## Packages To Keep Behind Facades

RBAC implementation packages should stay behind `integration/roles`:

- `domain/roles/model`
- `domain/roles/repository`
- `domain/roles/repository/postgres`
- `domain/roles/service/*`
- `domain/roles/shared`
- `domain/roles/usecases/*`
- `domain/roles/seeders/*`

Storage adapters should stay behind `integration/storage`:

- `storage/pgsql/*`
- `storage/redis/oidcstate`

Fiber auth adapters should stay behind integration facades unless intentionally
promoted:

- `http/fiber/legacysession`
- `http/fiber/oidcbearer`
- `http/fiber/oidclinkedsubject`

## Release Documentation Rule

Do not advertise direct implementation packages in README or release docs as a
consumer contract. If a host needs something that is not exposed, create a
stable facade first or document the temporary exception in
`HostSupportPackages`.
