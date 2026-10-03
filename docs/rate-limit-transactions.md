# Rate-limit admission and auth transactions

This follow-up replaces the process-local fallback introduced in `06f87ed2`.
PostgreSQL is again the only admission-event store for the PostgreSQL adapter.
There is no second in-memory history, timestamp deduplication, or retained bucket
map in `postgres.Store`. Equal timestamps still represent distinct attempts.

## Supported composition

Call rate-limited Runtime operations with the request context **outside** an
outer `AuthTransaction`. `Login`, `VerifyCredential`, `ChangePassword` and
`RequestPasswordReset` use `TakeRateLimit`. Their admission commits independently
before credential verification or subsequent auth writes. A later wrong password
or failed auth mutation does not roll back an admitted attempt. Other processes
and newly constructed Runtime instances observe those attempts in PostgreSQL.

The built-in PostgreSQL and testkit stores reject `TakeRateLimit` in a managed
auth scope with `goauth.ErrRateLimitTransactionUnsupported`. `errors.Is` works
through Runtime wrappers. The check happens before any additional SQL operation
or acquisition of testkit's already-held transaction mutex. It applies even when
the configured limit is not exhausted and to both correct and incorrect passwords.
A rejected composition does not admit an attempt or verify a password.

This is an explicit limitation, not support for nested admission backed by a
local approximation. The HTTP adapters expose a redacted 500 without a retry
hint: it is a host wiring error, not invalid credentials or rate exhaustion.
Never work around it by discarding the callback context, using `Background`,
opening a second connection under held locks, or retrying a mutation blindly.
Do not retain and reuse a transaction callback context after it finishes.

Use the Runtime's own transaction for an ordinary operation:

```go
account, err := runtime.ChangePassword(requestContext, request)
```

Do not wrap that call in `store.InAuthTransaction`. Hosts requiring an atomic
composition with unrelated host writes need a separately designed preparation /
admission contract; this change does not claim to supply one. Admission before
an outer transaction must not be followed by another nested call which repeats
admission. Direct mutation-store methods are trusted low-level interfaces, not a
substitute for Runtime authentication and security checks.

## Email quotas and testkit

Email issuance quotas (`IssueEmailChallenge` and `IssueEmailChange`) are separate
from credential-attempt admission. They still join auth/audit/enqueue writes and
roll back when issuance fails. Pending email state continues to be invalidated at
the security mutation, not at the end of the transaction.

Testkit uses its existing single Store mutex for both snapshots and rate events.
An unscoped call from another goroutine serializes with an active transaction;
a scoped call is rejected before locking. No root counter is updated behind a
working snapshot, so committing that snapshot cannot erase an admitted attempt.
The in-memory fixture is for tests; it is not a durable production limiter.

## Retry deadlines

The SQL limiter reads only the limit-th newest event in the inclusive window.
If it exists, its timestamp plus the window is the retry boundary. Otherwise it
inserts one event and commits. It no longer loads a complete event history into
Go memory. This preserves reduced-limit behavior and counts same-time attempts
separately. The exact cutoff remains inclusive; admission requires moving beyond
that boundary, and HTTP retry hints round upward to whole seconds.

## Rate-event maintenance

Hosts can schedule independent, bounded `postgres.Runtime.CleanupRateLimitEvents`
calls outside managed auth transactions. A batch bounds oldest candidates before
skipping locks, so a zero count does not prove an empty backlog. Preserve the
longest window used by all consumers sharing the table, including direct Store
callers with windows longer than the Runtime's 24-hour cap, plus clock skew and
request latency. See [the maintenance contract](rate-event-maintenance.md) for
cutoffs, confirmed-commit counts and the explicit schema 7 upgrade.

## Verification

Regressions cover rejection before database I/O, single-/multi-connection nested
calls, commit/rollback with existing attempts, concurrent testkit snapshots,
independent Store scopes, transactional email quota rollback, equal timestamps,
SQL visibility across fresh Runtime/Store instances and reduced limits. Earlier
email invalidation and retry tests are retained in focused composition files.

The editing session ran the committed standard-library boundary unit tests with
`-race` against byte-identical changed Store implementations in an isolated Go
1.23.2 harness. Root DTOs, event payloads and the PostgreSQL transaction helpers
were shims; no PostgreSQL server or full Runtime was executed. Those checks are
not whole-module verification. Formatting was checked with `gofmt`; project
`gofumpt`/gci/lint, full Runtime tests, integration, browser, vulnerability and
candidate gates require the declared Go 1.27.1 toolchain and dependencies.
No historical release-evidence status is changed by this follow-up.
