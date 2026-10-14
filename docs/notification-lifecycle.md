# Managed notification cancellation and receipt retention

These additive PostgreSQL Runtime operations require schema 12. Run
`postgres.Migrate` before starting the new binary, or use its authorized
`AutoMigrate` startup path. The migration adds the cancelled state and a scoped receipt-retention index;
it does not rewrite receipt rows. Existing migration files and checksums are
unchanged. Schema-11 binaries reject this newer schema; do not downgrade the
database marker to make an older binary start.

## Cancellation

`CancelNotification(ctx, id) (bool, error)` accepts a nonzero UUID delivery ID.
One atomic update can change only a `pending` or `blocked` row with a payload,
no lease ownership, an unspent configured worker attempt budget and both original
deadlines strictly after the Runtime clock. It never cancels a leased row,
including an elapsed lease whose transport outcome may be unknown. A missing,
already terminal, payload-free, deadline-expired or exhausted-budget row returns
`false, nil` and is unchanged.

Success stores terminal `cancelled`, clears ciphertext, nonce, additional data
and lease ownership, and preserves the delivery ID, attempt count, retry schedule,
deadlines and delivery timestamp. It records the safe operator reason
`operator_cancelled` in `last_failure`. `NotificationStats.Cancelled`
counts these retained rows. The worker cannot claim a cancelled row or complete
it under an old lease. This operation does not decrypt, send, revoke credentials,
reissue a code or inspect whether a referenced credential was superseded.

Cancellation stops future managed sends. It does not establish that an earlier
attempt was never accepted or delivered. Pending rows with previous attempts
can represent ambiguous historical transport results; preserve that uncertainty
in host UI and audit records. Do not label cancellation as confirmed nondelivery.

The method joins a managed auth transaction on the same database handle and
rejects a foreign scope. Hosts can pair successful cancellation with an audit
write through `SQLExecutor(ctx)` inside `InAuthTransaction`. Both writes roll
back if the callback fails. A joined boolean is provisional until the outer
transaction commits; publish success only after confirmed commit. Unknown commit
outcomes preserve `goauth.ErrOperationOutcomeUnknown` and must not be blindly
retried or treated as rollback.

## Queue-only receipt cleanup

`CleanupNotificationReceipts(ctx, retention, limit) (int64, error)` is an
explicit bounded pass with no automatic schedule. Zero retention defaults to
seven days; nonzero retention must be at least 24 hours. The limit must be
1 through 1000. The Runtime clock is sampled once, and a zero clock is rejected.

Only terminal `delivered`, `exhausted`, `expired` or `cancelled` rows
with NULL ciphertext, empty nonce/additional data and no lease can be deleted.
Both the original validity deadline and any delivery timestamp must be strictly
older than the cutoff. This retains a receipt for the requested interval after
the later of its original validity deadline and recorded provider acceptance.
The strict cutoff preserves boundary rows; a past acceptance timestamp cannot
remove a receipt whose original deadline is still live.

Live, in-flight, nonterminal and incompletely scrubbed rows remain. The pass
does not expire payloads or delete auth records, credentials, sessions,
identifiers, audits or transport-provider idempotency fences. Provider-owned
unknown/dispatching records need their own reconciliation and retention policy;
this queue-only cleanup must not be used to erase them.

A partial expression index supports the matching retained-cutoff predicate
and stable ordering. The operation uses `FOR UPDATE SKIP LOCKED` and joins a same-handle managed
transaction. A joined count is provisional until commit; errors return no
successful count, including an unknown commit. Locked rows can make a pass
return zero while eligible receipts remain. Hosts own deadlines and spaced
continuation; the row-change bound does not guarantee a time or scan-cost bound.
The existing broad `Cleanup`/`CleanupBatch` APIs keep their earlier predicates;
use this focused API when the stricter receipt-only contract is required.

## Verification

Focused tests cover cancellation state/deadline/budget guards, encrypted payload
scrubbing, stable metadata, host transaction rollback, worker lease fencing,
retention boundaries, bounded deletion, skipped locks, foreign transaction
rejection, commit uncertainty, schema-11 upgrade preservation, schema drift and indexed
batch selection over synthetic retained history.
Run the focused ordinary and integration tests, the clean external consumer,
and `make check` on the integrated revision before treating it as verified.
