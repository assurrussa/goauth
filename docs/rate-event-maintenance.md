# Bounded PostgreSQL rate-event maintenance

`postgres.Runtime.CleanupRateLimitEvents(ctx, request)` deletes one bounded batch
from `auth_rate_limit_events` and returns `(int64, error)`. It is a supported,
rate-event-only maintenance API. It does not expire notifications, remove audit
or session records, or call the existing broad `Runtime.Cleanup`. That API and
its `CleanupPolicy` behavior remain unchanged.

## Request and retention

`postgres.RateLimitCleanupRequest` has two fields:

- `Before time.Time`: only events with `occurred_at < Before` are eligible. An
  event exactly at the cutoff is retained. A zero value selects the configured
  Runtime clock minus 25 hours. An explicit cutoff must be no later than that
  same Runtime clock minus 24 hours.
- `Limit int`: required, from 1 through 1000 inclusive. Zero is not a default.

The clock is `postgres.Config.Runtime.Now`, defaulting to `time.Now`; this API
does not use `CleanupPolicy.Now`. A valid cutoff is a minimum safety guard,
not proof that retention is safe for every caller sharing the database.

Runtime-configured rate windows are capped at 24 hours, but direct
`postgres.Store.TakeRateLimit` requests accept any positive window. Choose a
cutoff that preserves the longest effective window across **all** consumers of
the shared `auth_rate_limit_events` table, plus allowances for clock skew and
request latency. Inventory direct Store callers as well as Runtime instances;
the maintenance Runtime cannot discover their policies or clocks. The default
25-hour retention is suitable only when it covers that complete requirement.
Use an older explicit cutoff when it does not. Coordinate changes to admission
windows and every cleanup scheduler, including any use of broad `Cleanup`, so
another caller cannot remove still-needed events.

For example, after validating the shared retention requirement, a host may run
one scheduled batch with the default cutoff:

```go
ctx, cancel := context.WithTimeout(maintenanceContext, 5*time.Second)
defer cancel()

removed, err := auth.CleanupRateLimitEvents(ctx, postgres.RateLimitCleanupRequest{
    Limit: 500,
})
```

Here `auth` is a `*postgres.Runtime`, and `maintenanceContext` is outside any
managed auth transaction. The timeout and limit are host choices, not a cleanup
cadence or a promise that execution always finishes within five seconds.

## Bounded selection and transaction outcome

Each call materializes at most `Limit` oldest eligible candidates ordered by
`(occurred_at, id)` **before** applying `FOR UPDATE SKIP LOCKED`. It then locks
and deletes available rows only from that candidate set. Locked candidates are
not replaced by scanning later eligible events, and the API has no internal
batch loop. Concurrent calls may therefore delete fewer rows than requested,
including zero, while a backlog remains. Neither zero nor a sub-limit result
proves that cleanup is complete; hosts choose cadence, retry/backoff and backlog
observation rather than busy-looping until a full batch disappears.

The operation owns an independent transaction. It rejects both same-database
and foreign managed auth transaction contexts before starting maintenance; it
does not join an outer `InAuthTransaction`. Schedule it separately, without
holding host transaction locks. Never discard a transaction callback's context
to work around this restriction.

The returned count is reported only after a confirmed commit. Every error
returns zero, including an ambiguous commit signaled by
`errors.Is(err, goauth.ErrOperationOutcomeUnknown)`. An unknown outcome is
neither confirmed success nor proof of rollback: some rows may already be gone.
Do not count the zero as a successful empty batch or infer an exact cumulative
deletion total from it. Preserve the error in host maintenance reporting and
reconcile state before claiming an exact result. A retry can delete another batch;
it does not recover the count from the uncertain attempt.

The index supports ordered candidate selection, and row limits restrict the
candidate set; neither establishes a wall-clock bound. Set context deadlines
and appropriate database timeouts, and monitor lock contention and maintenance
latency. Deadlines and `SKIP LOCKED` do not eliminate connection, relation-lock,
storage or commit delays.

## Schema 7 and rollback

Schema 7 adds a B-tree index on `auth_rate_limit_events (occurred_at, id)` for
ordered maintenance. Migration 6 and all earlier migration files and checksums
are unchanged. The upgrade preserves existing rate events and canonical auth
records; it does not run cleanup or select a host retention policy.

Use the supported `postgres.Migrate` or an already authorized host
`AutoMigrate` policy for the explicit upgrade. Index creation uses the normal
migration transaction and may take time or contend with writes on retained
history; plan the migration window. This library change does not deploy an
application, migrate production or authorize a cutover.

Schema-6 and older binaries reject schema 7 as a future schema at startup.
After upgrading, application rollback must use a schema-7-compatible binary.
Do not lower schema history, rewrite old migrations, or remove canonical state
to make an older binary start. Any backup restore is a separate operator-owned
recovery decision with its own data-loss and reconciliation requirements.

See [rate-limit admission and transactions](rate-limit-transactions.md) for the
independent admission contract and [notification expiry](notification-outcomes.md)
for the separate queue-only maintenance API.
