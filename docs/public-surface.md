# Public surface guide

`reference/externalconsumer/packages.go` is the authoritative supported import
manifest. `imports.go`, `manifest_test.go`, `public_surface_test.go`, and the
runnable external-consumer probe keep the declaration executable.

The supported packages are root Runtime, PostgreSQL, Redis, Fiber, OIDC
protocol/provider/verifier, RBAC, and testkit. `HostSupportPackages` stays
empty.

When adding or changing public API:

1. Verify the behavior belongs to a reusable Runtime or adapter boundary.
2. Search all workspace consumers before changing an exported symbol.
3. Keep PGX, Fiber internals, concrete SQL repositories, SQL rows, and host
   DTOs out of root contracts. Keep the supported dependency graph publicly
   resolvable without private module credentials.
4. Update `SupportedPackages`, the matching import manifest, and the public
   symbol compile test.
5. Extend the runnable clean-consumer example so it exercises the capability.
6. Update contract and migration documentation.
7. Run `make release-candidate-readiness` before tagging and the published
   clean-consumer probe for the intended tag after publication.

Only manifest packages are supported. Earlier v0.1 use cases remain in
`internal/legacy`, cannot be imported by external consumers, and are not all
replaced by the v0.2 Runtime. Their immutable tags remain available to
consumers that have not migrated. Importability alone does not make a package
supported.
