# goauth project contract

## Ownership

`goauth` owns canonical identity state, identifiers, local credentials,
realm-bound sessions and refresh families, recovery and email verification,
identity links, OIDC protocol behavior, RBAC, PostgreSQL schema, Redis OIDC
one-time state, encrypted notification events, and typed security audit events.

Hosts own HTTP route layout, cookies, redirects, frontend UX, membership and
projection tables, profile extensions, permission catalogs, environment
loading, delivery providers, and production rollout.

## Supported package boundary

External consumers use the exact packages in
`reference/externalconsumer.SupportedPackages`. The root package is the
transport-neutral Runtime; `postgres`, `redis`, and `fiber` are adapters;
`oidc`, `rbac`, and `testkit` are focused capabilities.

Legacy `core`, `local`, `session`, `service`, `usecases`, `domain`, `storage`,
`infrastructure`, `integration`, `http`, and `migrations` trees are migration
implementation details under `internal/legacy` and are not v0.2 public API.
The compiler rejects consumer imports of them.

## Schema lifecycle

The v0.2 baseline is authoritative for a fresh database. Detection of a v0.1
schema fails with a typed non-destructive error. Development/test reset requires
the exact confirmation constant; production migration is deliberately absent.

## Consumer contract

Consumers resolve published semver tags without committed local replaces. A
local sibling replace is development evidence only. Release readiness requires
the runnable published clean-consumer probe plus each host's own schema,
permission, and application gates.
