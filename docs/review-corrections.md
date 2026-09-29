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
This is separate from the hash-concurrency budget. Trusted hosts must not expose
subject-ID-only Runtime methods as unauthenticated public APIs.

## HTTP contracts

Fiber auth handlers, errors and protected middleware set `Cache-Control: no-store`.
Net/http retains its existing no-store JSON responses. Rate-limit errors retain
`errors.Is` compatibility and expose `RetryAfter() time.Duration`; both adapters
round this delay upward instead of replacing it with the default login window.
The store supplies the retry deadline. New activity may change subsequent
admission, and plain third-party sentinel errors retain the documented fallback
hints. An uncertain operation outcome always suppresses an automatic retry hint.
Password-reset request denials retain their enumeration-safe accepted response.

## OIDC corrections and remaining scope

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

The earlier review also raised a separate contract question: binding an already
issued OIDC authorization code to the subject security version. This branch does
**not** add that binding or claim it is present. The existing provider checks the
current active account at exchange, but logout-all/password reset do not explicitly
invalidate an outstanding code. The provider grant model needs a focused follow-up
with a persisted version, code-store round-trip tests and exchange regressions.
Do not describe this item as fixed or claim global pending-grant revocation.

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
make release-evidence-check EVIDENCE=/absolute/private/release-evidence.yaml
```

Use `public-preview/release-evidence.example.yaml` as the structure, copy the
per-case detail fields into every scenario, and record actual observations.
The manifest must identify clean HEAD, a tag resolving to HEAD, all 38 scenario
IDs, the AUTH requirement coverage, passing gates and owner approval. An excluded
optional profile needs its own `not_applicable_reason` and `reviewer`; a case
cannot silently exclude an advertised profile. Core and operational cases remain
required. Findings use explicit `release_blocking` and `status: resolved` for closed
blockers. These checks validate structure and declared source identity, not the
truth of evidence or a reviewer's authority.

Keep the final manifest outside the clean checkout or in a private release
artifact: committing a file containing its own commit SHA is circular. Historical
local summaries and the unfilled template intentionally fail the acceptance gate.
No evidence status is upgraded by the presence of a test or a new source file.

## Validation performed in this change session

Isolated copies of the standard-library-only auth clock, retry conversion, and
release-evidence validator passed `go test -race` on Go 1.23.2. The validator tests
exercise constructed test manifests; they do not certify this candidate. They do
not cover the YAML/Git command wrapper.

The project-declared Go 1.27.1 toolchain and dependency downloads were unavailable
in the execution container, whose GitHub DNS lookup failed. Full-module tests,
format/tidy/lint, PostgreSQL/Redis integration, browser acceptance, govulncheck,
exact-tag consumption and history/exposure review were not run in this session.
Do not merge on the basis of the isolated checks alone. Use the declared toolchain
to run `make prepare`, inspect any resulting changes, and then the canonical gate.
No tag, visibility change, production deployment or completed release is claimed.
