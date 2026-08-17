# Public surface guide

`reference/externalconsumer/packages.go` is the authoritative v0.2 import
manifest. `imports.go`, `manifest_test.go`, `public_surface_test.go`, and the
runnable external-consumer probe keep the declaration executable.

The supported packages are root Runtime, PostgreSQL, Redis, Fiber, OIDC
protocol/provider/verifier, RBAC, and testkit. `HostSupportPackages` stays
empty.

When adding or changing public API:

1. Verify the behavior belongs to a reusable Runtime or adapter boundary.
2. Search all workspace consumers before changing an exported symbol.
3. Keep PGX, external outbox, Fiber internals, concrete legacy repositories,
   SQL rows, and host DTOs out of root contracts.
4. Update `StablePublicPackages`, the matching import manifest, and the public
   symbol compile test.
5. Extend the runnable clean-consumer example so it exercises the capability.
6. Update contract and migration documentation.
7. Run `make check`, integration tests, vulnerability triage, and the published
   probe for the intended tag.

Only manifest packages are supported. Legacy implementation code is physically
under `internal/legacy`, so consumers cannot bypass the manifest by importing
concrete services, repositories, or migration runners.
