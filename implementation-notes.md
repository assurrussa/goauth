# Implementation Notes

## 2026-06-04 Project Initialization Docs

- Kept repository docs in English to match the existing README, RELEASING, and
  AUTH_INVARIANTS files.
- Treated `goauth` as a reusable published module, not a host application.
- Used local repo files as the source of truth and checked shared
  agent-context pages only after local grounding.
- Preserved the public-surface rule that `reference/externalconsumer` is the
  machine-readable support manifest.
- Added focused `docs/` files instead of expanding README with agent-only
  operational details.
- Recorded the repo-local Go cache requirement because raw `go list ./...`
  failed against the global Go build cache under the current sandbox, while the
  same command succeeds with `.go-cache/` paths.
- Did not touch existing modified files outside this documentation task.
## CMS role preset seeding (2026-07-15)

- Added generic host-owned role presets to the existing `integration/roles`
  seeder instead of putting CMS-specific policy into canonical auth.
- Preset slices are copied at the option boundary. Duplicate/reserved slugs and
  permissions outside the merged seed catalog fail before any seed writes.
- Built-in `super_admin` and `content_admin` behavior stays unchanged; concrete
  CMS role names and permission sets remain owned by `gocms`.

## CMS role scope clarification (2026-07-16)

- Kept the built-in `content_admin` permission set unchanged to avoid a silent
  privilege expansion. Its description now states the actual read-only RBAC
  scope and points administrators to the separate host-owned CMS roles.

## Private alpha release flow (2026-07-16)

- Prepared `v0.1.6` as the immutable release for the role-scope clarification.
- During the private alpha phase, a trusted maintainer may fast-forward the
  verified release commit directly to `master`; the tag and post-tag clean
  consumer gate remain mandatory even when a PR is skipped.

## Development gate efficiency (2026-07-31)

- Kept `make`, `make prepare`, `make check`, and release target names stable.
- Made `make check` source-read-only and replaced normal, repeated-race, and
  coverage test traversals with one race+coverage pass.
- Kept five-run race stress and HTML coverage as explicit diagnostics so
  investigations and release policy can still request them without charging
  every normal verification run.

## v0.2 secure Runtime release train (2026-08-18)

- The implementation is intentionally breaking and starts from a clean v0.2
  PostgreSQL schema. Existing v0.1 tags and migration files remain immutable.
- The stable consumer boundary is being reduced to the root Runtime plus
  PostgreSQL, Redis, Fiber, OIDC, RBAC, and testkit adapters. Legacy packages
  remain compile-checked under `internal/legacy`, where consumers cannot import
  them.
- Security-sensitive one-time state uses atomic store outcomes rather than
  read-then-delete APIs. Business outcomes are returned after the storage
  transaction commits so replay revocation and failed-attempt counters persist.
- Email is the only built-in confirmation identifier. Additional identifier
  schemes remain extension points and do not imply built-in delivery support.
- Runtime secrets use separate versioned JWT, token-HMAC, and outbox-AEAD key
  rings. Raw reset, refresh, and confirmation secrets must never be stored.
- Consumer migration proceeds in dependency order: goauth RC, goadmin and
  platform tooling, direct site/demo/vault consumers, then transitive hosts.
- Publication is a separate final gate. A local pass or an RC-compatible
  branch is not reported as a published release or production deployment.
- The toolchain moved from the planned Go 1.26.5 to Go 1.26.6 because 1.26.6 is
  the current security patch and removes reachable standard-library findings;
  `x/text` was raised to 0.39.0 for the same gate.
- The stable RBAC facade includes hierarchy-free management operations needed
  by host admin UIs. PostgreSQL role and permission replacement is
  transactional, while presentation DTOs remain host-owned.

## v0.2.1 canonical master integration (2026-08-30)

- Merged the frozen v0.1.7 maintenance line into the v0.2 Runtime line without
  changing the v0.2 schema or supported package manifest.
- Aligned `gonotify` to `v0.3.11` and Outbox core/PostgreSQL to `v0.12.0`.
- Locked the enumeration-safe recovery contract: an active unverified local
  account receives a one-time reset notification, but a successful password
  reset does not verify its email or promote its confirmation-scoped session.

## Standalone work toward a public candidate (2026-09-27)

- The initial v0.4 draft removed `internal/legacy` and its private module
  dependencies. That decision was superseded after review: the entire v0.1
  tree and its compile checks were restored. The new Runtime does not cover
  every previous use case. The nine-package supported import manifest remains
  unchanged; private dependencies currently block credential-free public CI.
- PostgreSQL managed delivery is opt-in through `NotificationSender`. The host
  owns the actual transport and supervises `RunNotifications` and `Cleanup`.
  The advanced encrypted-event sink remains available for custom integration.
- Native auth writes, encrypted enqueue, and audit share one transaction.
  Expected business outcomes commit outside the callback error path, notably
  wrong-code attempt counters. External sends run only after commit.
- Queue leases use token-checked completion. Sender retries are at least once
  with a stable delivery ID. Undecryptable events become individually blocked
  and are retried after one minute; expiry cleanup runs independently.
- The v0.2 SQL baseline stays byte-for-byte unchanged. An additive migration
  creates the delivery queue and checksum ledger under a PostgreSQL advisory
  lock; Runtime construction without AutoMigrate verifies the new schema.
- A pre-send database check suppresses codes already expired, consumed, or
  superseded at that instant. Concurrent invalidation during an in-flight
  external send remains possible without holding a database transaction across
  network I/O; the sender and host UX must tolerate that race.
- The refresh replay path now authenticates the secret before revoking a
  family, preventing a known selector with a forged secret from logging out
  the legitimate session.
- Reset issuance locks and checks the current account state; security changes
  retire existing reset records. A custom transaction alone does not select
  managed delivery or bypass its configured renderer.
