# Releasing goauth

This module is intended to be consumed as a published Go module at
`github.com/assurrussa/goauth`.

## Initial external release

- Use `v0.1.0` as the first published semver tag for the hard-cut canonical
  auth runtime.
- Keep the module path unchanged: `module github.com/assurrussa/goauth`.

## Current consumer state

Until `v0.1.0` is published and resolvable, repo-local consumers stay in
development mode:

- `backend/go.mod` requires `github.com/assurrussa/goauth v0.0.0`.
- `backend/go.mod` replaces `github.com/assurrussa/goauth => ./../goauth`.
- `goadmin/go.mod` requires `github.com/assurrussa/goauth v0.0.0`.
- `goadmin/go.mod` replaces `github.com/assurrussa/goauth => ../goauth`.

Do not remove these local replaces before the published module resolves. After
the tag is available, run `go get github.com/assurrussa/goauth@v0.1.0` in each
consumer:

```sh
go get github.com/assurrussa/goauth@v0.1.0
```

Then remove the local `replace` for `github.com/assurrussa/goauth`, run
`go mod tidy`, and rerun the consumer verification listed below.

## Release checklist

From the repository root, the local pre-publish gate is:

```sh
task goauth:release-readiness:local
```

The expanded checklist is:

1. Verify the module locally:
   ```sh
   cd goauth
   GOCACHE="$PWD/../tmp/gocache" go test ./... -count=1
   ```
2. Confirm the supported external surface:
   - `reference/externalconsumer` imports every package a host project may use,
     including the integration facades used by `backend` and `goadmin`;
   - `reference/externalconsumer/packages.go` is the machine-readable allowlist
     for the supported package surface;
   - `public_surface_test.go` references the exported constructors, option
     types, DTOs, and shared RBAC types that are intended to stay stable for the
     release.
3. Confirm `HostSupportPackages` is empty before tagging:
   - host wiring must go through stable integration packages;
   - do not grow this list silently. Move behavior behind an integration package
     or stop the release and document why a direct package path is unavoidable.
4. Verify the external consumer probe locally against the checkout:
   ```sh
   cd goauth
   GOMODCACHE="$PWD/../tmp/gomodcache" go run ./cmd/externalconsumerprobe --local-path "$PWD"
   ```
5. Verify the module can be copied as a separate repository root without
   resolving dependencies through the current checkout:
   ```sh
   task platform:module-export-check
   ```
   To rehearse the published clean-consumer path before GitHub tags exist, run:
   ```sh
   task platform:simulated-published-check GOAUTH_VERSION=v0.1.0 GOADMIN_VERSION=v0.1.0
   ```
   This uses temporary semver-tagged git repositories and strict scaffold
   checks without local module replaces.
6. Publish the repository/tag so a clean environment can resolve the module:
   - `go list -m -json github.com/assurrussa/goauth@v0.1.0`
7. Verify the published module from a clean temporary module:
   ```sh
   task goauth:externalconsumer:published GOAUTH_VERSION=v0.1.0
   ```
8. After the published module resolves cleanly, switch consumers:
   - update `backend/go.mod` and `goadmin/go.mod` from `v0.0.0` plus local
     replace to the published version;
   - run `go mod tidy` in both consumers;
   - rerun targeted auth verification in `goauth`, `backend`, and `goadmin`.
   Prefer the scripted switch once both `goauth` and `goadmin` tags resolve:
   ```sh
   task platform:switch-consumers-to-published GOAUTH_VERSION=v0.1.0 GOADMIN_VERSION=v0.1.0
   ```
9. After `goadmin` is also published and current repo consumers have been
   migrated, run the final aggregate gate:
   ```sh
   task platform:published-check GOAUTH_VERSION=v0.1.0 GOADMIN_VERSION=v0.1.0
   ```

## Release-visible behavior

- `goauth/migrations` exposes public `DatabaseConfig` and `RunWithConfig` so
  clean consumers can run canonical auth/RBAC migrations without importing
  `goauth/infrastructure/outbox`.
- `authjwtservice.WithProfileProvisioner` and
  `localjwt.Options.ProfileProvisioner` expose the reusable
  `authcore.ProfileProvisioner` hook.
- Existing canonical subjects can create or restore host projections during successful Local JWT login before token
  issuance.

## Notes

- Do not add new auth DDL or runtime compatibility fallback as part of the
  release.
- Do not treat `Subject.Kind` as the admin security boundary. Host admin access
  must require an admin membership/projection plus subject roles/permissions.
- Keep `users` and `administrations` as host projections/memberships. The
  canonical identity/auth source is `auth_subjects`, and the reusable RBAC source
  is `auth_subject_roles`.
- `cmd/externalconsumerprobe` is intentionally a release helper only. It is not
  part of the supported runtime API surface for consumers.
- If module publication is not yet available, stop after publish-readiness and
  keep the consumer switch pending.
