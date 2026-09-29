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

## 2026-09-29: PR #8 review follow-up

- Goal: fix the reviewed HTTP error contracts without changing canonical auth
  transactions or store APIs. Base: `d72ad96`; no initial local changes.
- Unknown commit outcomes must take precedence over joined cancellation,
  deadline, overload or throttle causes in both HTTP adapters and must not emit
  retry guidance. Plain infrastructure failures retain their existing mapping.
- Net/http account validation errors use explicit 422 codes, concurrent password
  change uses 409, and missing pending email change uses 404; unexpected internal
  errors remain redacted 500 responses.
- HTTP regression tests reproduced both findings before the fixes, including
  actual account handlers through authenticated middleware. They now check
  joined/wrapped error precedence, unchanged ordinary failures, redaction and
  retained canonical account, credential, session and notification state.
- Commit-outcome tests also cover cancellation and deadline errors returned by
  the driver's commit operation. No production transaction or store API changed.
- Final `make release-candidate-readiness` PASS: source guards, formatting,
  vet/lint (0 issues), race/coverage, local consumers, PostgreSQL/Redis,
  dump/restore and Chromium/HTTPS acceptance. Root coverage 83.9%, PostgreSQL
  80.7%; govulncheck reports no reachable vulnerabilities and three unreachable
  required-module findings.
- Independent read-only security/HTTP review found no issues in the six-file
  frozen snapshot. Actual PostgreSQL network-failure injection and an HTTP
  concurrent-password race are outside these added regression tests.
- Source fingerprint: `db4fde8f549eb9b36fcf7b91fa6c31d46c1632e2158c45c3b222211d9e65e8f7`
  over 129 non-documentation files. Full release-SHA acceptance, publication
  and deployment remain separate.

## 2026-09-29: PR #8 transactional event-sink review follow-up

- Goal: prevent PostgreSQL assembly from accepting an encrypted event sink
  outside its auth/audit transaction. Base: `d6b6087`; no initial local changes.
- Accepted boundary: reject custom `Runtime.EventSink` before DB connection or
  migration, as with custom audit and transaction hooks. Managed PostgreSQL
  assembly retains its native queue; custom enlisted integration belongs to
  direct root Runtime assembly. Public signatures and schema stay unchanged.
- Root owns constructor validation, its unit test and migration/ownership docs.
  One worker owns PostgreSQL integration fixtures and regressions; fixtures must
  inspect committed native queue rows rather than bypass the constructor guard.
- Validation: reproduce the constructor acceptance before fixing, prove failure
  causes no DB/schema changes, exercise durable auth/audit/enqueue rollback,
  independently review a frozen diff and run the complete candidate gate.
- Reproduced constructor acceptance on actual PostgreSQL before the fix; the
  regression now checks rejection with and without a sender and no schema
  creation. Unit coverage also rejects typed-nil event sinks before DB setup.
- Integration fixtures now read full encrypted events from committed native
  queue rows. Password-reset tests inject enqueue and mandatory audit failures,
  verify no reset/notification/issuance audit survives, then check successful
  issuance metadata, selector binding and Runtime decryption.
- Focused constructor and PostgreSQL regressions PASS. Independent read-only
  security/data review found no issues in the frozen ten-file snapshot and
  verified the existing public signatures, DB ownership and queue contracts.
- Final `make release-candidate-readiness` PASS: source guards, formatting,
  tidy verification, vet/lint (0 issues), race/coverage, local consumers,
  PostgreSQL/Redis, actual dump/restore and Chromium/HTTPS acceptance. Root
  coverage 83.9%, PostgreSQL 80.7%; govulncheck found no reachable vulnerabilities
  and three unreachable required-module findings.
- Source fingerprint: `d1455f514c8b2439719580b628bd1f5aefbffcbc13d5860ea17a1e353c26c987`
  over 130 non-documentation files. Full release-SHA acceptance, publication
  and deployment remain separate.

## 2026-09-29: PR #8 login-realm review follow-up

- Goal: map malformed and unregistered client login realms to explicit 400
  responses in both HTTP adapters. Base: `6fce6c5`; no initial local changes.
- Accepted contract: `invalid_realm` and `realm_not_registered`, fixed redacted
  messages and no retry guidance. Omitted/user realm login and existing 401/403
  boundaries remain intact; Runtime validation and public signatures unchanged.
- Reproduced 500 responses before the fix through real Runtime login handlers
  in both adapters, plus direct and wrapped error cases. Regression coverage
  includes invalid format/length, the default/user success path, unverified
  admin denial and retained canonical account/session state.
- Validation: targeted adapter tests, final `make check` and diff review.
  PostgreSQL/Redis, backup/restore, browser and host release gates from the prior
  fix are historical evidence and are not rerun for this classification change.
- Both complete adapter test suites PASS. Final `make check` PASS: 14 source
  guards, formatting/tidy verification, vet, lint (0 issues), race/coverage and
  the local clean-consumer probe. Root coverage remains 83.9%.
- Final diff self-review confirms fixed/redacted client responses, preserved
  unknown-outcome precedence and unchanged public signatures. Source SHA256:
  `f2fed1648ff2f7e4ef7ead74a58958ac9e6d8c59d81c578317a8353bbe1b6b8c`
  over 130 non-documentation files; full candidate acceptance is not rerun.

## 2026-09-29: PR #8 hasher, refresh-expiry and provider review follow-up

- Goal: fix the three new review threads against `2358ca9`; no initial local
  changes. Preserve native custom-hasher mismatch behavior, compute replacement
  refresh expiry at rotation time, and trim provider configuration whitespace
  while retaining the exact trailing slash in its issuer.
- Review lens: Security Engineering + Go/Backend + public-library compatibility.
  Custom verification outages need an explicit, compatible error marker;
  expired prepared access tokens must not consume a valid refresh token.
- Ownership: root handles password/refresh behavior, regression tests and docs;
  one fallback worker handles only the OIDC provider and its tests. A separate
  read-only reviewer will inspect the frozen combined diff.
- Validation: reproduce each finding before its fix, run focused root/provider
  regressions and real PostgreSQL refresh checks, then one final candidate gate.
  No schema, dependency, hosted workflow, release or deployment changes intended.
- Superseded: a pre-rotation JWT-expiry rejection bypassed replay that occurred
  after the authenticated snapshot. Independent review reproduced this race;
  root and PostgreSQL regressions also reproduced it. The expiry guard now runs
  after storage replay classification, rolling back ordinary expired rotation
  while retaining committed replay revocation/audit. Store-latency regressions
  cover access and refresh expiry during the transaction.
- Result: native bcrypt errors (raw/wrapped/joined) retain denial semantics in
  login, credential verification and current-password checks; a different
  replacement password remains accepted. Additive
  `ErrPasswordVerificationUnavailable` lets custom hashers report operational
  verification faults with their cause. Existing overload/cancellation/deadline
  errors also remain operational, without credential/session/notification writes.
- Root/provider suites and PostgreSQL refresh regressions PASS, including
  persisted expiry, absolute lifetime, second-precision JWT boundaries, rollback,
  concurrent replay revocation and committed audit. Regressions reproduced the
  original three findings and the intermediate replay regression before fixes.
  Final independent read-only review found no actionable issues; its old replay
  probe now observes replay detection and both winner credentials revoked.
- `make release-candidate-readiness` completed its check, PostgreSQL/Redis,
  local-consumer, vulnerability, aggregate-coverage and dump/restore components.
  The aggregate command then failed before browser execution because no
  Playwright module was selected. On the unchanged source, documented
  `GOAUTH_BROWSER_PLAYWRIGHT_MODULE` and `GOAUTH_BROWSER_CHROMIUM_EXECUTABLE`
  selected installed engines, and `make browser-acceptance` PASS. All component
  gates passed; the aggregate command was not rerun after this environment fix.
  The prior lint failure was confined to new test fixtures and was corrected.
- Final lint: 0 issues; race/coverage: root 84.3%, PostgreSQL 80.7%, provider
  82.4%. govulncheck: no reachable vulnerabilities, three unreachable findings
  in required modules. Active root/provider gopls diagnostics are clean.
- Source fingerprint: `da5e12096f55e53e5c927fda1b3847497a7d27d22a3fd1c3677f93dbd0ed7747`
  over 133 non-documentation files (SHA256 of sorted path/NUL/content-SHA256/LF
  entries). No schema, dependency or hosted-workflow changes. Existing public
  signatures are retained; the new error marker is documented and compile-checked.
  Real commit/network-latency injection, full release-SHA scenario acceptance,
  anonymous published-tag resolution and production deployment remain separate.

## 2026-09-29: PR #8 self-review and verifier-outage follow-up

- Goal: review the PR implementation and fix confirmed defects plus the new
  password-verifier outage discussion. Start: clean `3e427e3` on the PR branch.
- Review lens: Security Engineering + Go/Backend + transactional consistency.
  Root reviews Runtime/account/recovery and PostgreSQL auth transactions; an
  independent read-only reviewer checks OIDC verifier/provider and identity.
- Reproduce HTTP marker classification through both adapters and real auth
  handlers. Preserve unknown-commit precedence, redaction, canonical state and
  existing session validity. Investigate prepared-session expiry before writes.
- Validation: focused regressions before/after fixes, real PostgreSQL rollback
  checks for transaction changes, then one complete candidate gate with the
  documented installed browser engines. Public release acceptance stays separate.
- Confirmed own finding: delayed claims or session writes returned expired
  access/refresh pairs as successful registration, login or SSO login. A final
  validity check now runs after session storage in the same auth transaction,
  rolling back the session and any newly provisioned account/identity link.
- Independent OIDC review reproduced canceled unknown-key requests consuming
  the global refresh cooldown without a fetch. The verifier now rejects an
  already-canceled context before admission; shared fetches survive individual
  cancellation under a total HTTP timeout. Coalescing and failure backoff remain.
- HTTP marker cases and all 15 in-memory expiry cases reproduced failures on
  the original implementation. The focused root/HTTP follow-up now passes;
  native hasher mismatch behavior and refresh replay regressions remain green.
- Real PostgreSQL regressions reproduced all nine preparation failures and an
  actual delayed INSERT on the original head in a temporary source copy. The
  corrected cases pass with race detection, asserting durable rollback of
  accounts, credentials, identifiers, profiles, identity links and token state,
  followed by a successful same-identifier retry. Shared-flight cancellation,
  rotation and abandoned-fetch timeout regressions also pass with `-race`.
- Final independent read-only review found no actionable issues in the frozen
  14-file combined diff; its focused root/HTTP/verifier race tests passed and
  all file hashes matched before/after review. Root final diff review passed.
- Final `make release-candidate-readiness` PASS in one aggregate run: 14 source
  guards, formatting/tidy verification, vet/lint (0 issues), race/coverage,
  PostgreSQL/Redis, clean local consumers, govulncheck, aggregate coverage,
  actual dump/restore and Chromium/HTTPS acceptance. Browser engine selection
  used documented environment overrides; no tooling/dependency change needed.
- Source fingerprint: `71c1be9e53f1f72ac1f139c17520af51aea8b081aa8f94d19bcafe5e154ed62c`
  over 137 non-documentation files. Only these final evidence lines were added
  after the frozen review/gate. No schema, public signature, dependency or
  hosted-workflow changes. Commit/response latency, live IdP conformance, full
  38-case release-SHA acceptance and published/production adoption stay unverified.

## 2026-09-29: PR #9 review follow-up

- Goal: close the Runtime error, OIDC backoff test and host-evidence findings,
  plus the formatting/lint failures on `da60bf55`, in the existing PR branch.
- Preserve canonical subject locking, upstream-error backoff, public Go
  signatures, schema version 3 and the historical acceptance manifests.
- Root owns Runtime/OIDC/HTTP regression updates and final validation; one
  bounded worker owns the evidence CLI and its scoped YAML lint allowance.
- Evidence must include passing site/admin checks with the exact candidate
  goauth SHA and recorded host/dependency versions. Local replacement remains
  explicit; neither test fixtures nor old host smoke reports become evidence.
- Runtime missing-subject and infrastructure-failure regressions, public HTTP
  headers and verifier backoff/cooldown checks now pass with race detection.
- Evidence CLI integration is complete, including actual subprocess tests of
  temporary clean/dirty Git checkouts, exact-tag identity, malformed YAML and
  read-only behavior. YAML imports remain confined to the evidence CLI.
- Final `make release-candidate-readiness` PASS on Go 1.27.1: 14 source guards,
  tidy/format checks, vet/lint (0 issues), race/coverage, PostgreSQL/Redis and both
  local consumers, govulncheck, real backup/restore and Chromium/HTTPS acceptance.
  Root coverage 84.6%, PostgreSQL 80.6%, provider 82.9%, verifier 91.6%; no reachable
  vulnerabilities, three unreachable findings in required modules.
- A fresh independent read-only review found no actionable P1/P2. An earlier
  reviewer inadvertently read author notes; that pass is not used as the
  independent sign-off. Root final diff review and source hash consistency pass.
- Source fingerprint: `ed3236b571d5df3d24deeeb0494b4b4ec4f5979a1dc37aa454b2d8c3b57a625c`
  over 158 non-documentation files, unchanged through review and the gate. Only
  validation notes changed afterward. Disposable services were removed.
- Actual site/admin acceptance at the new candidate, full 38-case release-SHA
  evidence, anonymous tag resolution and publication remain separate.
