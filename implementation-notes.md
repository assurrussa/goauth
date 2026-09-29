# Implementation Notes

## v0.5.0 candidate implementation (2026-09-28)

- Accepted scope: transactional auth writes/audit/native encrypted notifications;
  prepare hooks and JWT before session creation and refresh consumption; strict
  replay revocation; explicit offline JWT vs current-session authentication.
- External identity keys are exact issuer/sub strings. Verified-email auto-link
  defaults to `["*"]` when configuration is nil; an explicit empty list disables
  new auto-links. There are no production identities requiring legacy relinking.
- Harden OIDC verification, inherit the default password blocklist, restrict
  destructive schema reset to owned objects, and add net/http plus one runnable
  PostgreSQL browser/JSON example. Preserve the native notification queue.
- Root owns runtime/storage/testkit/public contracts and integration. Separate
  workers own OIDC and nethttp/examples. Independent security/race review follows
  the implementation freeze.
- Validation: focused behavior tests, PostgreSQL/Redis integration, browser smoke,
  then `make release-candidate-readiness`. Publication, tag creation, and public
  visibility changes are separate and have not been authorized in this stage.
- Released baseline is v0.4.1; candidate is v0.5.0. No tags are rewritten.
- Implemented on `tasks/v0.5-auth-hardening` above `070b1f3`; changes remain
  uncommitted. PostgreSQL assembly enforces its local audit sink; custom root
  assembly explicitly owns transaction participation. `LockAccount` and
  `PeekRefresh` are required store contracts. See `docs/v0.5-migration.md`.
- Independent security/concurrency review found reset JSON fallthrough and a
  PostgreSQL audit override. Both were fixed, regression-tested and re-reviewed.
  Browser host security received additional source review without new findings.
- Final `make release-candidate-readiness` passed after those fixes: lint 0
  issues; race tests; PostgreSQL/Redis integration; both local consumer probes;
  no reachable vulnerabilities. Root coverage 83.6%, PostgreSQL 80.7%.
  gopls retained stale cross-file diagnostics for `LockAccount`; compiler, vet,
  lint and race/integration checks all resolved the actual current API.
- Real browser evidence is recorded in `examples/nethttp/README.md`: signup,
  notification delivery, verification, login, refresh, logout/all, CSRF and
  bearer/cookie isolation passed. Password-change/reset submission was blocked
  by automatic approval review requiring user hand-off; email-change confirmation
  was not completed. Multi-tab clicks completed, but no global request count was
  retained. These limits do not become browser acceptance through unit tests.
- Updated the existing shared platform wiki and added a sanitized candidate
  snapshot, preserving its historical v0.2.1 release evidence. Publication,
  production deployment, visibility/security-channel verification, history/tag
  secret review and the published v0.5 consumer probe remain a separate stage.

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

## Standalone public candidate and legacy retirement (2026-09-28)

- The legacy v0.1 use cases under `internal/legacy` and their private module
  dependencies (`assurrussa/*`) have been permanently retired after confirming
  all core auth operations are fully supported by the canonical `goauth.Runtime`
  and its adapters.
- The module has zero private dependencies and resolves cleanly in public CI
  without `PRIVATE_GO_MODULES_TOKEN`.
- PostgreSQL managed delivery is opt-in through `NotificationSender`. The host
  owns the actual transport and supervises `RunNotifications` and `Cleanup`.
  The advanced encrypted-event sink remains available for custom integration.
- Participating native auth writes, encrypted enqueue, and audit share one
  transaction in managed notification operations. This is not a general
  Runtime unit of work; a transaction context is rejected by a Store bound to
  a different `*sql.DB` handle.
  Expected business outcomes commit outside the callback error path, notably
  wrong-code attempt counters. External sends run only after commit.
- Queue leases use token-checked completion. A sender call reserves one attempt
  before the external effect; retries use a stable delivery ID but can stop
  without acceptance at expiry or the attempt limit. Undecryptable events
  become individually blocked, emit a payload-free observer event, and are
  retried after one minute; expiry cleanup runs independently.
- The v0.2 SQL baseline stays byte-for-byte unchanged. An additive migration
  creates the delivery queue and checksum ledger in one PostgreSQL transaction
  under a transaction-level advisory lock. Invalid Runtime configuration is
  rejected before schema mutation; construction without AutoMigrate verifies
  the new schema.
- A pre-send database check suppresses codes already expired, consumed, or
  superseded at that instant. Concurrent invalidation during an in-flight
  external send remains possible without holding a database transaction across
  network I/O; the sender and host UX must tolerate that race.
- Challenge issuance carries the email and security version read by the
  Runtime into the Store transaction. PostgreSQL locks and compares the current
  identifier and subject before recording the code, so an email change that
  commits between the Runtime read and issuance cannot create a code for the
  former recipient. Confirmation invalidates earlier challenges.
- The refresh replay path now authenticates the secret before revoking a
  family, preventing a known selector with a forged secret from logging out
  the legitimate session.
- Reset issuance locks and checks the current account state; security changes
  retire existing reset records. A custom transaction alone does not select
  managed delivery or bypass its configured renderer.

## Accepted browser/native/admin implementation (2026-09-28)

- Goal: local v0.5 candidate plus real site/admin acceptance. Publication and deployment remain separate. Baseline snapshots preserve the pre-existing dirty goauth work. Host branches start from site `4614ee60e0839c4fb25f5a020301721844ba5a36` and goadmin `4152e0a490e786bd25e1623477b6ab41f05c79f0`.
- Accepted contracts: browser access/refresh HttpOnly; readable `SSIDR=1` hint; explicit native Bearer API; coordinated switch and re-login; existing opaque admin session; strict refresh replay with no grace; explicit ZITADEL access-token profile.
- Root owns runtime/password/errors, admin refresh consistency, native notification assembly and final gates. Helpers own site HTTP/frontend/OpenSpec and OIDC/pilot respectively. Host compatibility uses temporary modfiles; no committed local replacements.
- Validation: focused regressions, real PostgreSQL/Redis atomicity, HTTPS browser scenarios, isolated ZITADEL pilot, one candidate gate, host gates and independent security/race review. Existing notes are historical evidence, not the current candidate result.
- Resolved approval boundary: the initial broad site write was rejected; a concrete tested patch passed a safer automatic review and was applied. Host sources are integrated; no production deployment or publication occurred.

- Integrated: bounded password work and TTLs, explicit native and cookie-only
  site routes/frontend, managed encrypted notification supervision, opaque admin
  owner/version journal and safe CSRF binding, explicit ZITADEL profile.
- Actual scope evidence: real site HTTPS/PostgreSQL browser+native lifecycle,
  two-tab single rotation, admin PostgreSQL/Redis refresh/permissions/revocation,
  live ZITADEL canonical registration/link/re-login; engine absence fails invoked
  suites. Final aggregate gates and independent delta review are recorded in the 2026-09-29 result below.
- Added public same-origin browser and real backup/restore gates to candidate
  readiness. OPS-03/04 remain distribution/history tasks, not executed claims.

## 2026-09-29 Local auth profile implementation result

Review lens: Security Engineering + Go/Backend + Browser/Mobile boundaries.

- Implemented the accepted browser HttpOnly access/refresh and marker policy,
  explicit full native token API, opaque admin owner/version journal and native
  managed encrypted delivery; final source review found no open exploitable
  blocker in these advertised profiles. Two import-guard findings were fixed
  and re-reviewed with targeted positive/negative fixtures.
- Final root `make release-candidate-readiness` PASS: lint 0, fmt/vet,
  race/coverage (root 83.9%, PostgreSQL 80.7%), local consumers, real PG/Redis,
  actual disposable dump/restore and public-example Chromium/HTTPS lifecycle.
  `govulncheck` found no reachable vulnerabilities; three required-module
  findings are unreachable, not a blanket clean dependency claim. PHC fuzz
  executed 467499 cases in the bounded 10-second run.
- Goadmin `make check` PASS with a temporary candidate module file, resources
  and local consumer; independent actual PostgreSQL/Redis admin refresh,
  permissions/membership and canonical logout-all acceptance PASS.
- Site `task validate` PASS with temporary local candidate composition. Final
  canonical PostgreSQL/HTTPS browser and native lifecycles PASS, including two
  tabs and one rotation, delivery-confirmed reset/email/password transitions.
  Frontend lint/typecheck, 14 regressions and production compile PASS; CMS
  prerender was explicitly disabled for that compile.
- Real isolated ZITADEL PKCE/host/PostgreSQL identity pilot PASS. Scope is the
  resource-server/identity subset; full frontend SSO cookie callback and
  production rollout are not verified. The stale draft callback requirement
  was aligned with the accepted P4 subset and recorded as superseded.
- `task platform:repo-check` was executed and FAILED at unrelated gouploads
  generated-file drift. Its exact generated side effects were reversed from
  the saved patch. Remaining auth/import/second-host/export guards passed;
  runtime import inventory was reconciled with four imports already in the
  original site HEAD and the explicit host CSRF dependency. No whole-platform
  green claim is made.
- Evidence: `docs/public-preview/release-evidence.local.yaml`. It preserves all
  38 required IDs and separates complete cases from narrower passed checks.
  The full security/fault/rollback/release matrix is still open; public tag,
  anonymous resolution, history/asset audit and production acceptance remain
  separate. No commit, tag, publication or deployment occurred. Existing user
  changes, released host pins and old notification drain handlers are retained.

## 2026-09-29: PR #8 integration with current master

- Goal: remove PR #8 conflicts while retaining user commit `4bf77db` and the
  accepted changes from PR #6/#7. Merge target: `8d99216`.
- Combined the explicit exact-tag, isolated public consumer tooling with the
  existing browser and backup/restore candidate gates. Workflow configuration
  is retained exactly from master; no additional hosted jobs are introduced.
- Preserved PR #7 AUTH IDs, all 38 release-blocking cases, per-case observation
  fields and required successful release gates. Selected v0.5 profile details
  now live in `docs/public-preview/candidate-assembly.md`; the pre-commit local
  snapshot remains historical evidence, not full release-SHA acceptance.
- Validation: `make release-candidate-readiness` PASS on the merged source:
  source-guard regressions 14/14, fmt/vet/lint (0 issues), race/coverage,
  PostgreSQL/Redis and local consumers, dump/restore, Chromium/HTTPS. Root
  coverage 83.9%, PostgreSQL 80.7%; no reachable vulnerabilities, with three
  unreachable required-module findings. gopls could not load the newly merged
  helper files; the compiler, vet and lint checks above passed.
- Source fingerprint: `609bdcc81a3c0ad1fe23fe6fe14bb1c8cb2dc57937e25f57c86fd70bcedb3a9e`
  over 127 non-documentation files. Only master release tooling/workflows and
  Makefile differ from the prior source snapshot; auth Runtime/adapters/stores
  and OIDC are unchanged.
- Documentation checks PASS: original AUTH meanings, exact PR #7 security
  specification, all 38 blocking scenario entries, complete evidence fields,
  relative file links and absence of machine-local paths. Full release/host
  acceptance and anonymous published-tag resolution remain open.
