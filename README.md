# goauth

`goauth` is the canonical auth module used by the host applications in this
workspace. It owns transport-neutral auth behavior, canonical auth storage,
and canonical migrations.

## Scope

`goauth` owns:

- canonical auth reads and writes for subjects, local credentials, sessions,
  refresh tokens, OIDC refresh tokens, password reset state, confirmation state,
  email-change state, and SSO identity links;
- reusable subject-based RBAC storage, services, use cases, cache, guards, and
  seeders under `domain/roles`;
- canonical migrations under `migrations/`;
- transport-neutral auth services and use cases used by `backend` and
  `goadmin`.

`goauth` does not own:

- host HTTP/Fiber wiring, cookies, and request/response contracts;
- host-specific permission catalog extensions, admin UI policy, session payload
  enrichment, or profile/membership projection tables;
- host-specific UX and admin/frontend policy.

## Supported External Surface

The exact published package allowlist is compile-checked in
`reference/externalconsumer`. That package imports the supported external
surface currently consumed by `backend` and `goadmin`.
The same directory also keeps the machine-readable `SupportedPackages` manifest
used by the external consumer probe command at `cmd/externalconsumerprobe`.

The supported surface is the explicit package list in
`reference/externalconsumer.SupportedPackages`. That list is built from:

- `StablePublicPackages`: the reusable API intended for new external
  consumers;
- `HostSupportPackages`: a compatibility bucket that must remain empty before
  the first broad external release.

In prose, the stable surface currently covers core auth types, shared auth
types, local auth services, session services, OIDC/SSO types and services, the
integration kits, subject RBAC types/services, permission middleware, auth
JWT/invalidator/confirmation services, canonical storage facades, and embedded
migrations.

Concrete PostgreSQL/Redis adapters, Fiber auth middleware, RBAC repository
wiring, seeders, and cleanup use cases are exposed through `integration/*`
packages instead of direct implementation package paths. New consumers should
depend on the integration kits and facades.

If a package is not listed in `SupportedPackages`, it is not part of the
supported external API even if it exists in this module.

Anything under `internal/`, the compile fixtures under `reference/`, and the
legacy persistence shapes in `model/` are not part of the supported external
runtime contract.

## Consumer Expectations

- Host repos stay projection-only and must not become auth sources again.
- `auth_subjects` is the shared identity/profile/auth source. Host `users` and
  `administrations` tables represent application memberships/projections by
  `subject_id`.
- `auth_subject_roles` assigns roles to any canonical subject. Admin access is the
  combination of an admin membership/projection plus required roles/permissions;
  `Subject.Kind` is routing metadata, not a security boundary.
- Keep ID meanings separate: local `id` is a projection primary key, `uuid` is a
  public/app projection identifier exposed in Go core as `PublicID`, and
  `subject_id` is the canonical auth/RBAC key.
- Host projection tables do not keep duplicate auth/profile shadow columns.
  Runtime auth/profile reads must use `auth_subjects` and
  `auth_local_credentials`.
- Missing host projections are repaired via provisioning, not runtime fallback.
- Consumers should depend on a published semver tag of
  `github.com/assurrussa/goauth`; local `replace ../goauth` is only a temporary
  monorepo development mode.

See [RELEASING.md](RELEASING.md) for the publish and consumer-switch checklist.
See [AUTH_INVARIANTS.md](AUTH_INVARIANTS.md) for canonical identity,
transaction-boundary, and subject ID invariants that must stay true across
`backend`, `goadmin`, and external consumers.
For a clean temporary-module verification workflow, use
`go run ./cmd/externalconsumerprobe --local-path <checkout>` before publication
and `go run ./cmd/externalconsumerprobe --version <tag>` after publication.
From the repository root, the task wrappers are
`task goauth:externalconsumer:local` and
`task goauth:externalconsumer:published GOAUTH_VERSION=<tag>`.

## Host Installation Path

1. Run `goauth/migrations` before host migrations so canonical auth and RBAC
   tables exist before host projections reference them. Clean consumers should
   call `migrations.RunWithConfig` with the public `migrations.DatabaseConfig`
   instead of importing infrastructure packages for migration config.
2. Build the canonical storage set through `integration/storage`.
3. Wire auth behavior through `integration/localjwt`, `integration/adminsession`,
   and `integration/oidc` instead of reading host `users` or `administrations`
   as auth sources.
4. Wire RBAC through `integration/roles`. Add host permission definitions via
   the catalog/seed APIs instead of forking the RBAC schema.
5. Keep host tables as projections/memberships. They may cache fields for
   efficient lists and screens, but canonical auth decisions must use
   `auth_subjects`, auth stores, and `auth_subject_roles`.
