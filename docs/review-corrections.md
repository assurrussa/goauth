# v0.5 review corrections

Base: `01b2a114a6b65a8de12197d60305acf41d4bf7d9`.
Branch: `fix/review-security-release-hardening`.

These changes are an implementation candidate, not release evidence. The dated
`public-preview/release-evidence.local.yaml` remains unchanged and must not be
interpreted as observations for this branch.

## Security boundaries

Email-change issuance now locks and revalidates the account snapshot, including
active status, security version and primary identifier. Confirmation and email
verification recheck active status under the same canonical subject lock. The
PostgreSQL store checks activity even when called without the root Runtime.

Password reset, email verification and email-change confirmation evaluate expiry
after acquiring their subject and one-time-record locks, immediately before the
protected mutation. Runtime transactions carry their configured clock; direct
PostgreSQL store calls include measured lock-wait time relative to the supplied
request time. This is not a guarantee that a response arrives before expiry or
that transaction commit and network delivery have no latency.

Every canonical security-version change that revokes subject security state also
invalidates pending email-change records and outstanding email-verification
challenges in the same transaction. This includes password change/reset,
subject-status change, email change and logout-all. Existing schema version 3 and
migration files are retained: records are invalidated transactionally rather than
adding a parallel version column. Custom stores must preserve this behavior.
Re-enabling a subject does not revive those records. A repeated logout-all reports
only newly revoked sessions; it still advances the subject security version.

Password changes have a separate subject-keyed attempt bucket, using the Runtime's
configured login window and limit. Admission is checked before password hashing.
The Runtime first resolves local credentials so an unknown subject retains
`ErrCurrentPasswordInvalid` without attempting an invalid rate-event foreign key.
This is separate from the hash-concurrency budget. Trusted hosts must not expose
subject-ID-only Runtime methods as unauthenticated public APIs.

## HTTP contracts

Fiber auth handlers, errors and protected middleware set `Cache-Control: no-store`.
Net/http retains its existing no-store JSON responses. Rate-limit errors retain
`errors.Is` compatibility and expose `RetryAfter() time.Duration`; both adapters
round this delay upward instead of replacing it with the default login window.
The store supplies the retry deadline. Email challenge and email-change quotas
use the limiting event in each active rolling window; when resend and quota
limits overlap, the latest deadline is returned. New activity may change
subsequent admission, and plain third-party sentinel errors retain the
documented fallback hints. An uncertain operation outcome always suppresses an
automatic retry hint.
Password-reset request denials retain their enumeration-safe accepted response.

## OIDC corrections

The verifier selects only compatible RSA signing keys for RS256, ignores
incompatible entries in mixed JWKS documents, and rejects different compatible
keys sharing one `kid`. Identical repeated keys are harmless. A malformed
compatible signing key still fails closed; unsupported algorithms have not been
enabled. `VerifiedAccessToken.Audience` now means the configured audience that was
actually validated, not the first audience in the token.

Failed discovery/JWKS refreshes receive a one-second backoff in addition to the
existing unknown-key cooldown and shared-flight coordination. Expired caches
remain fail-closed. A failed unknown-key refresh does not disable unexpired cached
keys. Caller cancellation still does not cancel another caller's shared fetch.

OIDC refresh-store commits use the same uncertain-outcome classification as the
canonical Runtime. Callers must not automatically resubmit a potentially consumed
refresh token after `ErrOperationOutcomeUnknown`; start authentication again.
Strict replay revocation is retained.

Authorization codes now persist the subject `SecurityVersion` from issuance.
The provider first rejects a stale authentication snapshot, then binds the code
to its exact subject and version. Exchange requires the same active subject and
version and rechecks code expiry after subject resolution. Thus a password reset,
logout-all or other version change completed between issuance and exchange makes
the outstanding code invalid. This is a version-bound grant check, not a distributed
transaction spanning the IdP, Redis, PostgreSQL, signing and response delivery.

Code stores must round-trip the new field unchanged. The built-in Redis JSON
store already serializes the complete record. Old records without a version are
rejected, not silently upgraded to the current version; restart authorization.
This affects only in-flight authorization attempts and needs no PostgreSQL schema
reset or migration. See [v0.5 migration](v0.5-migration.md).

## Regression coverage added

- Root Runtime: inactive account rejection, expiry after the subject lock,
  pending email invalidation, and subject-keyed password-change limits.
- PostgreSQL: independent connections, an observed `pg_blocking_pids` wait,
  clock advancement beyond expiry, no credential/email/version mutation, and
  repeated logout-all counts. These are integration-tagged tests, not mocks.
- HTTP: no-store on successful and malformed token requests, wrapped/joined retry
  deadlines and uncertain-outcome precedence.
- OIDC verifier: mixed and ambiguous JWKS, sequential fetch-failure backoff,
  and multiple audiences.
- OIDC provider: stale issuance, version changes, inactive/wrong subjects,
  versionless codes, expiry during resolution and the unchanged positive flow.
  A real Redis integration test verifies version round-trip and one-time consume.
- Release evidence: stale/missing/duplicate scenarios, weakened blocking flags,
  missing observations, unapproved exclusions and blocked gates are rejected.

## Public-preview evidence gate

The existing executable candidate and exact-tag gates retain their roles. Full
public-preview acceptance additionally has a distinct target:

```sh
make public-preview-readiness VERSION=<new-tag> EVIDENCE=/absolute/private/release-evidence.yaml
```

For evidence validation alone, after those gates have actually passed:

```sh
make release-evidence-check VERSION=<new-tag> EVIDENCE=/absolute/private/release-evidence.yaml
```

The composed `public-preview-readiness` gate passes its selected `VERSION` to
the evidence CLI. `candidate.tag` must match that version even when another tag
points at the same commit. Standalone `release-evidence-check` may omit
`VERSION`; then it checks the manifest's own tag and does not bind a selected
published-version gate.

Use `public-preview/release-evidence.example.yaml` as the structure, copy the
per-case detail fields into every scenario, and record actual observations.
The manifest must identify clean HEAD, a tag resolving to HEAD, all 38 scenario
IDs, the AUTH requirement coverage, passing gates and owner approval. An excluded
optional profile needs its own `not_applicable_reason` and `reviewer`; a case
cannot silently exclude an advertised profile. Core and operational cases remain
required. Every finding must use a YAML boolean `release_blocking`; a true
blocking finding must have `status: resolved`. These checks validate structure and
declared source identity, not the truth of evidence or a reviewer's authority.

The `host_checks.site` and `host_checks.admin` entries are mandatory. Each must
record a passing outcome, its host commit, resolved goauth version and candidate
SHA, an explicit replacement flag, the acceptance command and redacted evidence.
Local replacement is permitted only with the same declared candidate SHA; it
does not establish anonymous tag availability. A shared `browser_and_hosts` gate
cannot stand in for these individual observations.

Keep the final manifest outside the clean checkout or in a private release
artifact: committing a file containing its own commit SHA is circular. Historical
local summaries and the unfilled template intentionally fail the acceptance gate.
No evidence status is upgraded by the presence of a test or a new source file.

## Earlier validation

The original implementation session verified isolated standard-library copies on
Go 1.23.2 because its container could not obtain the declared toolchain or
dependencies. Those historical checks were not a full candidate gate.

The review follow-up passed `make release-candidate-readiness` on Go 1.27.1. This
includes source guards, tidy/format verification, vet, lint (zero issues),
race/coverage tests, disposable PostgreSQL/Redis integration, both local consumer
probes, govulncheck, a real database backup/restore and Chromium/HTTPS acceptance.
Root coverage is 84.6%, PostgreSQL 80.6%, provider 82.9% and verifier 91.6%.
Govulncheck found no reachable vulnerabilities and three unreachable findings in
required modules. A fresh independent review found no actionable P1/P2.

The email-change missing-subject outcome is preserved; infrastructure lock errors
still propagate without notification or state consumption. The OIDC regression
checks both the one-second upstream-error backoff and the unknown-key cooldown,
including old-cache validity and recovery. The evidence tests cover missing,
failed, incomplete and stale host observations plus actual YAML/Git CLI execution
on temporary checkouts, including proof that the CLI does not modify HEAD or
working-tree status.

The checked source fingerprint is
`ed3236b571d5df3d24deeeb0494b4b4ec4f5979a1dc37aa454b2d8c3b57a625c`
over 158 non-documentation files. Source stayed unchanged through the final
review and gate; only these validation notes were updated afterward.

Constructed evidence fixtures do not certify the candidate's observations.
Actual site/admin acceptance at this candidate, the complete 38-case manifest,
anonymous published-tag consumption and history/exposure review remain separate.
No tag, visibility change, production deployment or completed release is claimed.

## Latest review validation

The follow-up on `8be1ede5` covers the selected-version evidence binding,
strict finding booleans, event-based email retry deadlines, and the additional
missing-subject password-change regression. The latter was reproduced against
PostgreSQL before the fix. Separate Standards and Spec reviews found no further
actionable issue after correction.

On Go 1.27.1, `make check`, `make integration` and `make vulnerability-check`
passed. This includes lint with zero issues, race/coverage tests, real disposable
PostgreSQL/Redis and both local external-consumer probes. Root coverage is 84.6%
and PostgreSQL coverage is 80.8%. Govulncheck reports no reachable vulnerabilities;
three findings are confined to unused code in required modules.

The email tests cover hourly/daily windows for verification and email change,
overlapping resend limits, reduced quotas, exact cutoff behavior and HTTP retry
headers. Candidate/publication gates and new host acceptance evidence were not
part of this follow-up verification.
