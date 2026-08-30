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

## Maintenance dependency alignment (2026-08-30)

- Prepared `v0.1.7` from the `master` maintenance line without merging or
  modifying the separate `v0.2` line.
- Aligned `gonotify` to `v0.3.11` and both Outbox core and PostgreSQL backend
  modules to `v0.12.0`; no goauth runtime, migration, or supported-package
  contract changed.
- Kept publication exact-versioned because the already published `v0.2.0`
  remains the version selected by `@latest`.
