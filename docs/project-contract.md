# goauth Project Contract

## Role

`goauth` is the canonical auth/RBAC module for Go host applications. Its module
path is `github.com/assurrussa/goauth`.

The repository is maintained as a reusable platform module. It should remain
independent from concrete host repositories such as `backend`, `blog`, or
`goadmin`, except where those projects consume the published public surface.

## Ownership Boundary

`goauth` owns:

- canonical auth reads and writes for subjects, local credentials, sessions,
  refresh tokens, OIDC refresh tokens, password reset state, confirmation
  state, email-change state, and SSO identity links;
- canonical PostgreSQL migrations for the `auth_*`, OIDC, SSO, and RBAC tables;
- transport-neutral services and use cases for Local JWT, password reset,
  confirmation, token cleanup, admin email-change cleanup, and OIDC cleanup;
- reusable subject RBAC storage contracts, services, guards, cache, use cases,
  and seeders;
- host-facing integration kits under `integration/*`;
- clean-consumer release probes under `cmd/externalconsumerprobe`.

Host applications own:

- HTTP UX and cookie policy;
- frontend routes and screens;
- process-specific wiring and environment loading;
- host projection tables such as `users` and `administrations`;
- app-specific permission catalog extensions;
- business-domain features that use auth/RBAC.

## Package Boundaries

Use `core` and `shared` for stable contracts and DTOs. Use `integration/*` when
building host wiring. Use `migrations` to run canonical auth/RBAC migrations
without importing infrastructure packages.

`domain/roles/*`, concrete `storage/*`, lower-level `http/fiber/*`, and
`infrastructure/*` packages may be importable, but they are not automatically
public API. Promote behavior through an integration facade when it is intended
for external consumers.

## Current External Consumer Model

Clean consumers should import the stable packages listed in
`reference/externalconsumer.SupportedPackages`.

The expected new-project model is a separate consumer repository that imports
published semver tags. Local `replace` directives are acceptable only for
explicit sibling-development checks, not as evidence that the published module
works for a real external consumer.

## Identity Invariants

`auth_subjects` owns stable auth identity. Host profile rows are projections or
memberships keyed by canonical `subject_id`.

Do not rebuild canonical subject IDs from numeric admin IDs, public IDs, or host
projection UUIDs. If a canonical subject is missing a real `subject_id`, the
auth adapter should fail hard instead of inventing a fallback identity.

See `AUTH_INVARIANTS.md` for the detailed invariant set.
