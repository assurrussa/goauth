# goauth project contract

## Ownership

`goauth` owns canonical identity state, identifiers, local credentials,
realm-bound sessions and refresh families, recovery and email verification,
identity links, OIDC protocol behavior, RBAC, PostgreSQL schema, Redis OIDC
one-time state, encrypted notification queueing and worker state, and typed
security audit events.

Hosts own HTTP route layout, cookies, redirects, frontend UX, membership and
projection tables, profile extensions, permission catalogs, environment
loading, the notification sender and worker lifecycle, delivery providers, and
production rollout.

## Supported package boundary

External consumers use the exact packages in
`reference/externalconsumer.SupportedPackages`. The root package is the
transport-neutral Runtime; `postgres`, `redis`, `nethttp`, and `fiber` are adapters;
`oidc`, `rbac`, and `testkit` are focused capabilities.

The retired v0.1 implementation is absent from the current source tree. Its
former package paths are not supported imports; immutable v0.1 tags preserve
the old release for consumers that still need it.

The native PostgreSQL notification queue is selected through a host-provided
`goauth.NotificationSender`. The host owns final delivery, starts and stops the
worker, and schedules cleanup. The lower-level encrypted event sink remains an
advanced integration path through direct root Runtime assembly. The PostgreSQL
constructor rejects custom event sinks so auth state, mandatory audit and native
enqueue share its database transaction.

## Managed PostgreSQL transactions

`postgres.Runtime.InAuthTransaction` coordinates canonical, audit, RBAC and host
SQL writes on one database handle. The host obtains a context-scoped
`SQLExecutor`; only the outer owner commits. Join concurrent operations before
returning from its callback and do not retain its context or executor afterward.
RBAC snapshots run in a standalone repeatable-read, read-only transaction. A
managed auth context returns `rbac.ErrSnapshotTransactionUnsupported`, preserving
the normal auth transaction isolation.
RBAC callback registration is synchronized, with outcome hooks executed after
unlocking. Successful writes reserve cache bypass before commit; rollback releases
only its own reservations. Managed writes reserve at callback registration, and
standalone writes reserve before committing their owned transaction. Cache
invalidation runs only after durable commit. Each invalidation has a two-second
deadline detached from request cancellation, including lock waits; custom
invalidators must honor it.
Timeout keeps committed writes successful. Failed invalidation bypasses cache
reads to authoritative PostgreSQL until successful invalidation. An unknown RBAC
write outcome keeps cache reads bypassed for the wrapper lifetime; a read-only
snapshot commit error cannot make cached permissions uncertain. Database failures
still fail closed.

A transaction uses one SQL connection. Consume and close result sets before
starting another operation on it; serialize mixed Query/Exec work. This callback
synchronization does not provide a general concurrent SQL query scheduler.
Idempotent role assignment uses one Exec without changing the assignment's
`created_at`; repeated assignments can create an additional PostgreSQL row version.

## Schema lifecycle

The v0.2 baseline is authoritative for a fresh database. Detection of a v0.1
schema fails with a typed non-destructive error. Development/test reset requires
the exact confirmation constant; production migration is deliberately absent.

## Consumer contract

Consumers resolve published semver tags without committed local replaces. A
local sibling replace is development evidence only. Release readiness requires
the runnable published clean-consumer probe plus each host's own schema,
permission, and application gates.

## Public-preview completion specification

[The public-preview specification pack](public-preview/README.md) defines target
profile contracts, security acceptance scenarios, local site/admin verification,
implementation work packages, and publication/support evidence. The pack itself
does not promote supported imports or claim that the target checks have passed.
Cookies and CSRF remain optional outside browser integrations; the supported
cookie-authenticated profile must supply tested CSRF protection. Actual host
session behavior is verified locally before a new credential model is introduced.

[Candidate assembly decisions](public-preview/candidate-assembly.md) record the
v0.5 browser/native/admin/OIDC composition. Local verification is recorded
separately from the complete release acceptance criteria.
