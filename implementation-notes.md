# Implementation notes

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
- Independent static security review of the changed snapshot, followed by
  re-review of the RBAC correction, found no remaining actionable P1/P2. This is
  scoped change review, not an independent audit or OIDC certification.
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
- Independent static security/storage review found no remaining actionable P1/P2
  in this follow-up delta. Non-integration edited Go files have no gopls diagnostics;
  build-tagged integration behavior was verified by the compiler and live tests.
- Final diff and public-facing documentation passed whitespace/local-path checks.
  Hosted CI remains unrun; this is local candidate verification only.
