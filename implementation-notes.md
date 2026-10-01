# Implementation notes

## 2026-10-01: Delivery deadlines and handled RBAC errors (local working tree)

Goal: fix the supplied review and PR discussion
[r4152303917](https://github.com/assurrussa/goauth/pull/11#discussion_r4152303917).
Base HEAD: `a15e8fcd001e893c3e39ec04d942ae1f349f4357`, initially clean.
Review lens: worker reliability, authorization cache consistency and operation
atomicity. Preserve public signatures, dependencies and migrations.

- Child delivery deadlines expire/retry/exhaust only the delivery, preserving
  the running worker. Ambiguous reservation cancellation reconciles persisted
  attempts under the owned lease token. pgx query-canceled errors are classified
  only when the child context is done. Parent cancellation stops the worker;
  genuine storage errors remain fatal, including errors coincident with timeout.
- All RBAC mutations reserve bypass before SQL and share a write helper.
  Managed mutations serialize their savepoints and roll back operation-local
  changes even if the host handles the error and commits other writes. Recovery
  uses a bounded detached context; failed recovery aborts the outer transaction.
- One guard and one outcome callback are reserved per transaction/cache pair,
  preserving synchronized registration, rollback and unknown-outcome behavior.
  Separate cache wrappers and overlapping transactions retain separate guards.
- Provider signing rejects blank active key IDs and preserves valid IDs verbatim.

Validation:

- New tests reproduced callback fan-out and blank signing IDs on the original
  implementation. The handled-error regression failed for all six cases against
  an exact temporary copy of the base SHA and live PostgreSQL. Worker regressions
  reproduced the deadline failure before its correction.
- Focused race checks passed for deadline/parent/storage outcomes, concurrent
  RBAC writes, commit boundaries, rollback, savepoint recovery failures and
  signing IDs. Live PostgreSQL checks cover all five handled business-error paths,
  SQL-error recovery, continuation of host writes, retained metadata/permissions
  and 64 concurrent assignments with one invalidation.
- Go diagnostics for edited implementation files are clear of errors; existing
  style hints remain. Some new test files lacked gopls metadata; compilation,
  lint and race tests checked them through the full gate instead.
- Final `make release-candidate-readiness`: PASS with CI-matching gci v0.14.0,
  gofumpt v0.11.0 and official golangci-lint v2.14.0. Formatting, tidy, vet, lint,
  race/coverage, PostgreSQL/Redis integration, both clean local consumers,
  govulncheck, backup/restore and actual HTTPS browser acceptance all passed.
  Disposable integration containers, volumes and network were removed.
- Coverage thresholds passed: root 84.7%, OIDC provider 87.2%, RBAC 85.8%,
  PostgreSQL 82.5%, Redis 100%. Govulncheck found zero reachable vulnerabilities;
  three findings remain in required modules outside called code paths.
- Independent read-only review of this diff and new tests found no actionable
  defect. Its scope was transaction/cache correctness and worker outcomes;
  it was not a complete security audit.
- Verified source fingerprint:
  `61213eddcad2505e777303b965a6b6bfdedd38cf502ee1df80492e758e15ef2a`.
  It is SHA-256 of sorted `path + NUL + SHA256(file bytes) + LF` records for
  tracked and nonignored files, excluding this notes file. It stayed unchanged
  throughout the full gate and identifies local sources, not a published commit.
- Final diff and public-document local-path checks passed. No commit, push,
  new hosted CI run, tag or exact-tag public module verification was performed.

Hosted CI for the base SHA passed:
[run 36821855136](https://github.com/assurrussa/goauth/actions/runs/36821855136).
This verifies the committed base only; the findings above supersede the earlier
review verdicts. The new local validation is recorded separately above.

## 2026-10-01: Pre-commit RBAC bypass, CI and JWK follow-up (historical validation)

Goal: resolve PR discussion
[r4151920361](https://github.com/assurrussa/goauth/pull/11#discussion_r4151920361)
and the supplied follow-up review. Base HEAD:
`fd2062fc05cc9fefabbcc785cb3d3b5b2a0d62e9`; working tree was clean at the start.
Review lens: authorization concurrency, PostgreSQL transaction outcomes and
release-tool correctness. Public signatures, dependencies and migrations are
preserved; the existing RS256 key profile is enforced consistently.

- Successful managed RBAC writes reserve bypass when their outcome callbacks
  register. Standalone writes reserve before committing. This closes the gap
  between PostgreSQL commit visibility and post-commit cache invalidation.
- Rollback, callback panic/cancellation and known commit rejection release only
  their own pending guards. Unknown commit marks the cache uncertain before
  releasing its guards. Commit invalidation retains the bounded detached context,
  failed-cache fallback and conservative generation handling.
- Provider JWKS rejects different RSA public keys sharing one `kid`, while
  permitting identical duplicates as the verifier does. The JWK encoder rejects
  blank key IDs; provider signing rejects explicit algorithms other than RS256.
- `fmt-check` preserves formatter exit status. gci explicitly receives `/dev/null`
  stdin: its v0.14.0 source automatically includes inherited pipes as Go input.
  Six regression checks exercise tool errors, format diffs and piped stdin.
- CI pins golangci-lint v2.14.0, verified from its official checksummed binary
  built with Go 1.27. Trigger scope, single job, runner size, cancellation and
  timeout stay bounded; no extra hosted job or matrix is introduced.

Validation status:

- New regressions reproduced stale grants at both commit boundaries, incompatible
  JWK/signing metadata and swallowed formatter failures before implementation.
- Focused race checks passed, including existing managed commit/rollback/unknown
  outcome tests. gci v0.14.0 reproduced the CI `StdIn EOF` error with inherited
  piped stdin; the corrected formatter gate passed the same input scenario.
- Final `make release-candidate-readiness`: PASS with CI-matching gci v0.14.0,
  gofumpt v0.11.0 and the official golangci-lint v2.14.0 binary. The gate includes
  formatting, tidy, vet, lint, race/coverage, PostgreSQL/Redis integration, both
  local clean consumers, govulncheck, backup/restore and the real HTTPS browser
  scenario. Disposable integration containers were removed after verification.
- Coverage thresholds passed: root 84.7%, OIDC provider 87.1%, RBAC 85.8%,
  PostgreSQL 81.5%, Redis 100%. Govulncheck reports zero reachable vulnerabilities;
  three findings remain in unused code of required modules.
- The full suite exposed a strength-test fixture publishing two different keys
  under one `kid`. It now uses a separate ID for the 2048/3072-bit active key,
  preserving issuance, parsing and publication checks under the new invariant.
- Verified source fingerprint:
  `c0e1cb7598a85e9739e1bff691b923af384f7632c03268712376365101af3868`.
  It is SHA-256 of sorted `path + NUL + SHA256(file bytes) + LF` records for
  tracked and nonignored files, excluding this notes file to avoid self-reference.
  It identifies the verified working tree, not a new commit or published tag.
- Final diff and public-document local-path checks passed; CI YAML parsed and
  its linter pin was verified. This does not establish hosted runner success.
- Hosted CI for base SHA `fd2062f`: FAIL
  ([run 36815937502](https://github.com/assurrussa/goauth/actions/runs/36815937502)).
  Its log confirms the Go 1.26-built linter/Go 1.27 mismatch and swallowed gci error.
  No hosted run for this local correction has been claimed.
- Public module/tag verification: not run. Independent audit: not performed.

## 2026-10-01: Snapshot, PKCE and JWK follow-up (historical validation)

Goal: fix the three confirmed findings in the supplied follow-up review.
Base HEAD: `c2a73cf40ac0a85384bd0ec636793d96791193b6`; the earlier no-findings
assessments below are superseded by this review. No dependency, migration,
client-authentication policy or cache invalidation state machine change is needed.
Review lens: Go/backend, authorization security and storage consistency.

- PR discussion `r4151727953`: standalone read-only RBAC snapshots now commit
  through `commitAuthTransaction`, retaining unknown-outcome classification
  without marking the write cache uncertain. Mutation commits keep their guard.
- PKCE rejects malformed verifier grammar and S256 encodings at the authorization
  and exchange boundaries. Verifiers/challenges are never whitespace-normalized;
  valid flow fixtures use the RFC 7636 Appendix B vector. Entropy remains a client
  generation requirement, not something the provider can establish from format.
- Provider and verifier share `oidc.ValidateRS256SigningJWKMetadata`; optional
  `use`/`alg` remains supported and third-party incompatible keys are still filtered.
  The new helper is included in public-surface and executable consumer probes.
- The conservative cache invalidation generation handling is retained; the
  supplied review identifies additional fallback, not stale authorization.

Validation for this working tree:

- Before implementation, new regressions reproduced ambiguous snapshot-commit
  cache poisoning, weak/normalized PKCE secrets and incompatible provider metadata.
- Focused package tests passed for PostgreSQL, OIDC/provider/verifier and the
  consumer probe. Go diagnostics for the edited implementation files are clean.
- Final `make release-candidate-readiness` with the shared Go cache root passed:
  formatting, tidy, vet, lint, race/coverage, PostgreSQL/Redis integration, both
  clean local consumer probes, govulncheck, PostgreSQL backup/restore and the
  actual HTTPS browser scenario. Browser runtime paths were selected through
  `GOAUTH_BROWSER_PLAYWRIGHT_MODULE` and `GOAUTH_BROWSER_CHROMIUM_EXECUTABLE`.
- Coverage thresholds passed: root 84.7%, OIDC provider 87.4%, RBAC 85.8%,
  PostgreSQL 81.6%, Redis 100%. Govulncheck found zero reachable vulnerabilities;
  three findings remain in unused code of required modules.
- Verified source fingerprint:
  `821cd29a254119f32f3e96e0824008464f70bd5402d28977fa710f7751d34a85`.
  It is SHA-256 of sorted `path + NUL + SHA256(file bytes) + LF` records for
  tracked and nonignored files, excluding this notes file to avoid self-reference.
  It identifies the local working tree, not a commit or published tag.
- Historical diff review found no additional actionable issue in those corrections;
  whitespace and public-document local-path checks passed. This is scoped local
  verification, not an independent security audit or hosted CI result.

This section records local verification before commit `fd2062f` was published.
Hosted CI subsequently failed on that commit, and the later pre-commit cache
finding above supersedes its review verdict. Historical gates do not certify the
new working tree or a release tag.

## 2026-10-01: initial optional-module review corrections (historical validation)

Goal: resolve the current branch review findings while preserving canonical
identity, transactional audit, migration history and dependency versions.
Review lens: Go/backend, security and storage consistency.

- Base: `27ea3f4c1ea6c366fd8654297889f100c4f43af9`, initially clean.
- OIDC: the initial optional-PKCE behavior was subsequently narrowed to
  confidential clients; public clients now always require S256 (see follow-up).
  The configured authentication-method list is enforced, unknown methods fail
  construction, and access-token parsing explicitly validates RS256/exp/iat/issuer.
- Persistent client registries can supply an authoritative secret verifier;
  legacy static configuration remains supported. No plaintext fallback after
  verifier rejection. Public clients deliberately use `none`.
- HTTP: disabled notification delivery returns a stable 501 code. Fiber uses
  explicit session/JWT methods, caps handler bodies at 1 MiB, and documents its
  supported handler subset instead of expanding unrelated transport APIs.
- RBAC: suspect cache reads bypass to PostgreSQL. Successful invalidation
  restores a transiently failed cache; unknown commits keep this wrapper in
  bypass mode. Pending invalidations bypass before external I/O. Read-through fills and
  invalidation share a separate lock; readers never wait behind invalidation.
  Generation changes discard late cached grants. Database failures still deny.
- Notifications: reserve a send and renew the owned unexpired lease together;
  recheck event expiry, bound reservation+send by one deadline and reclaim an
  expired claim before spending an attempt. Delivery remains at least once.
- Public hygiene: standard Go cache defaults with host overrides; private local
  evidence excluded from published sources; historical host inventory removed.
  Previous implementation notes and local evidence were retained privately.
  Existing Git history/tags are untouched, so historical exposure needs its
  own review even when HEAD is clean.

Validation completed on the final code snapshot:

- `make release-candidate-readiness`: PASS. Includes formatting/tidy/vet/lint,
  full unit race/coverage, local runnable consumer, PostgreSQL/Redis race and
  coverage gates, PostgreSQL runnable consumer, govulncheck, actual pg_dump/
  pg_restore and HTTPS Chromium acceptance. The installed browser was selected
  through the documented runtime overrides; no project dependency changed.
- Coverage: root 84.7%, OIDC provider 84.2%, RBAC 85.8%, PostgreSQL 81.3%,
  Redis 100%; all required package thresholds passed. Govulncheck reports no
  reachable vulnerabilities and three findings in unused required-module code.
- Targeted live PostgreSQL tests prove failed-invalidation bypass, recovery and
  owned-lease renewal/reclaim. Channel-controlled race tests prove that blocked
  invalidation does not block authorization and late read-through fills cannot
  restore revoked grants.
- Historical static security review and RBAC re-review reported no remaining
  actionable P1/P2 at that time. The later findings above supersede that verdict;
  this was scoped review, not an independent audit or OIDC certification.
- Gitleaks 8.30.1 scanned all fetched branches/tags/PR refs (73 reachable commits,
  28 refs before this commit) with `git --log-opts='--all --full-history'` and
  full redaction. All 29 raw history matches and 32 publication-source matches
  were fixed test/example credentials, reviewed as false positives. Ignored
  developer caches are outside publication scope. Reports remain private.
- Reviewed public-facing files contain no machine-local paths. Make environment
  probes verified configured Go defaults, shared-root overrides and individual
  overrides. Public symbols compile in the supported clean consumer.

Local gates do not establish completed public-preview profile acceptance or
public distribution. No public release, deployment, repository visibility or
protection change is included. The owner authorized sending the changes but
reported unavailable CI quota. The commit uses `[skip ci]`; the draft PR records
local verification and explicitly leaves hosted CI at the committed SHA unrun.

## 2026-10-01: repeat review and PR 11 snapshot correction

Goal: close review findings against `5722c316d74fe0dd0e360699a19541dc15c3a475`.
Review lens: security, Go/backend and storage consistency. The owner chose to
keep the repository private; existing history and tags remain unchanged.
Hosted CI remains intentionally skipped because the owner has no available quota.

- PR 11 discussion `r4148669264`: PostgreSQL `Snapshot` rejects a managed auth
  context with `rbac.ErrSnapshotTransactionUnsupported`; standalone snapshots
  retain repeatable-read/read-only isolation without changing normal auth writes.
- Public OIDC clients always require S256. Confidential-client PKCE remains
  configurable. JWK/provider/verifier paths reject weak or malformed RSA keys;
  signing validates the private key and matching pair. Typed nil secret verifier
  functions fail closed with an error.
- Each post-commit cache invalidation has a two-second detached deadline, including
  the delegate lock wait. Timeout bypasses cached authorization while committed
  writes remain successful. Generation checks prevent an older success from
  clearing a newer failure; fresh completed invalidation can recover the cache.
  External invalidators must honor context cancellation; no background worker
  masks an invalidator that ignores this contract.
- New public symbols are included in the public-surface and clean-consumer probes.
- Regression coverage includes a live PostgreSQL commit paused between snapshot
  queries, managed-context rejection with a usable outer transaction, deadline
  expiration, blocked read-through fills and overlapping invalidation outcomes.

Validation completed on the final follow-up source snapshot:

- Targeted live PostgreSQL snapshot/cache regressions passed with the race
  detector, integration build tag and an uncached test run.
- `make release-candidate-readiness`: PASS, including tidy/format/vet/lint
  (zero issues), full unit race/coverage, PostgreSQL/Redis race/coverage, both
  runnable clean-consumer probes, govulncheck, actual backup/restore and HTTPS
  Chromium acceptance. An initial format-only failure was corrected before
  this complete successful gate.
- Coverage thresholds passed: root 84.7%, OIDC provider 86.6%, RBAC 85.8%,
  PostgreSQL 81.6%, Redis 100%. Govulncheck found zero reachable vulnerabilities;
  three required-module findings remain in unused code.
- Historical static security/storage review reported no actionable P1/P2 in that
  delta; the later snapshot/cache finding on the same SHA supersedes the verdict.
  Non-integration edited Go files had no gopls diagnostics; build-tagged integration
  behavior was verified by the compiler and live tests.
- Final diff and public-facing documentation passed whitespace/local-path checks.
  Hosted CI remains unrun; this is local candidate verification only.
