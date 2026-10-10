# Bounded broad maintenance

`postgres.Runtime.CleanupBatch(ctx, policy, perCategoryLimit)` performs one
explicit, opt-in maintenance pass. It does not schedule itself. Existing
`Runtime.Cleanup`, queue-only `ExpireNotifications`, rate-only
`CleanupRateLimitEvents`, and strict-profile `SessionOIDCState.CleanupExpired`
keep their established public behavior. No migration is added.

## Limits and continuation

`perCategoryLimit` must be 1 through 1000; zero is invalid. Each returned numeric
field is independently capped at that value. `RefreshFamilies` and
`OIDCRefreshFamilies` are additionally capped at 32. These are per-category
bounds, not one global row budget. Across a successful call, the maximum is
`12 * perCategoryLimit + 2 * min(perCategoryLimit, 32)` row changes: at limit 1000,
12,064 changes. Notification expiry is an envelope update; receipt cleanup is a
separate physical deletion. A row can therefore count in both categories in one
pass if both existing predicates are satisfied.

The result embeds the unchanged `CleanupResult` and adds `OIDCRequests` and
`OIDCCodes`. Canonical subject locks are capped at `min(perCategoryLimit, 32)`;
the bounded family and session parents are deleted only when their children are
empty, so parent cascades add no uncounted deletions. Refresh chains are removed
from an unreferenced predecessor in safe prefixes, with one shared token budget
per profile. A chain longer than the limit continues across calls. Cyclic custom
history is retained rather than breaking references to force progress.

Call again later to continue eligible rows. To drain a fixed retention window,
capture a clock once and supply `CleanupPolicy.Now` returning that same value on
each pass. There is no cursor or `has_more` flag. Busy subjects, locked rows,
dependent parents and remaining chain prefixes can leave backlog after any
pass, including a zero-count pass. Neither zero nor a sub-limit result proves
exhaustion. Do not busy-loop until zero; hosts own cancellation, deadlines,
bounded work windows and spaced scheduling.

Only row changes are bounded. The canonical predecessor lookup, candidate
searches and `SKIP LOCKED` scans may examine more rows, and no wall-clock or query
work bound is promised. Rate cleanup retains its existing stricter bounded
candidate-before-lock query. This API does not add indexes or change the schema.

## Retention and security

The pass samples `CleanupPolicy.Now` exactly once. Zero retention fields keep
the existing defaults: 24 hours for expired auth records, 25 hours for rate
events, 90 days for audit events and 7 days for notification receipts. Validation
retains the existing minimums; the new API additionally rejects a zero clock.
Choose the rate retention to cover the longest window used by every consumer
of the shared table, plus clock-skew/request-latency margin. The 24-hour minimum
alone does not establish that a host's longer custom window is safe.

Canonical refresh history is eligible only when the fixed session expiry,
session revocation or family revocation is strictly before the retained cutoff.
Token expiry and consumption alone never qualify it. Consumed selectors,
HMAC digests, ancestor links and replay markers remain available while the
family/session is live or within retention. Family-only revocation does not remove
a live session. Generic recovery, rate, audit and receipt comparisons remain
strict `<`; notification and OIDC expiry retain their existing `<=` comparisons.
The host's existing retention policy is neither shortened nor replaced.

Notification expiry uses the same bounded queue SQL as `ExpireNotifications`,
with the cleanup policy's clock. It clears ciphertext, nonce, additional data
and lease ownership without inventing a delivery outcome. An in-flight provider
may already have accepted a request; lease fencing prevents a later completion
from overwriting expiry. Receipt deletion remains independently retention-bound.
The pass does not delete subjects, credentials, identifiers, profile/RBAC state
or subject retirement tombstones.

## Transactions and errors

An active managed transaction is rejected before SQL, whether it belongs to the
same Runtime database or a foreign handle. Same-handle rejection uses
`postgres.ErrAuthTransactionAlreadyActive`; foreign scopes keep their existing
rejection. This broad API never joins a managed scope. The existing standalone
notification expiry API still joins its supported same-handle scope.

Four independent transactions run in order: notification expiry, OIDC cleanup,
canonical refresh/session cleanup and generic cleanup. Every phase releases its
locks before the next. The canonical phase locks subjects before their dependent
rows, preserving supported rotation/revocation serialization. Generic work
starts only after those locks have been released.

Returned counts describe only confirmed committed phases. If a later phase
fails, earlier confirmed counts remain in the result; counts from the failed
phase are omitted. The pass is not globally atomic. A commit whose outcome is
uncertain preserves `goauth.ErrOperationOutcomeUnknown`; omitted counts are not
proof of rollback. A subsequent pass can delete another batch and does not
reconstruct an uncertain earlier count. Cancellation propagates to each phase;
already committed work remains committed.

## Validation

The focused source tests cover per-category and aggregate bounds, physical table
deltas (including cascade detection), long canonical/OIDC chains, multiple
families/sessions on one subject, merge/cycle safety, fixed-cutoff continuation,
strict boundaries, live replay evidence, busy-row/subject continuation,
notification scrubbing, clock/transaction rejection and classified commit errors.
Public surface and generated clean-consumer probes exercise the additive API.

Before calling an integrated candidate ready, run the focused ordinary and
PostgreSQL integration tests, the existing notification/rate/OIDC/refresh
retention and concurrency regressions, the clean consumer, and `make check` on
the exact integrated revision. The source candidate alone is not runtime proof.
