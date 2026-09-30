# Implementation notes

## 2026-10-01: optional-module review corrections

Goal: resolve the current branch review findings while preserving canonical
identity, transactional audit, migration history and dependency versions.
Review lens: Go/backend, security and storage consistency.

- Base: `27ea3f4c1ea6c366fd8654297889f100c4f43af9`, initially clean.
- OIDC: optional PKCE must work end to end; supplied PKCE requires S256.
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
