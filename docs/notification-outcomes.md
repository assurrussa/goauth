# Managed notification outcomes and expiry

`NotificationSender` returns nil only when its documented handoff succeeded. Ordinary errors keep the existing retry policy. Return `goauth.ErrNotificationRejected` (wrapping is allowed) only for positively known terminal non-delivery, for example an explicit gateway simulation or final provider rejection. Never use it for timeouts, lost responses, or ambiguous provider acceptance. The PostgreSQL worker records `state=exhausted`, `last_failure=sender_rejected`, keeps `delivered_at` NULL, and scrubs encrypted payload, nonce, and AAD under the current lease compare-and-swap. Exhausted means unsuccessful terminal delivery, including either attempt-budget exhaustion or explicit sender rejection. A numeric attempts count is not a number of emails delivered.

`postgres.Runtime.ExpireNotifications(ctx, limit)` is optional bounded host maintenance. Limit is 1..1000; the Runtime clock supplies the cutoff. It retires only expired encrypted notification envelopes, skips locked rows, clears payload and lease, and leaves all receipt rows, reset records, sessions, identities, and audit events intact. Calls join an existing managed transaction on the same database and reject foreign transaction contexts. Repeated batches are idempotent. Hosts may schedule bounded calls but must choose their own cadence.

Expiry records that no more attempts are allowed; it is not evidence that a provider never accepted an in-flight request. A late sender result cannot overwrite expiry or another lease. Hosts must preserve their own safe metadata for unknown outcomes instead of interpreting expired as definitely undelivered. This API does not call broad Cleanup or adopt any retention policy for other records. Existing cleanup APIs and generic-error retry behavior remain unchanged.

The expiry API requires PostgreSQL schema 5. Migration 5 adds a partial B-tree on
`(valid_until, id) WHERE ciphertext IS NOT NULL`; prior migration files and their
checksums remain unchanged. Schema verification checks the index definition and
the validated `valid_until <= delete_after` constraint before using the indexed
cutoff. Index creation runs in the normal migration transaction and may take time
on retained history; use a planned migration window. Bound host calls by a timeout
as well as the row limit, since locked rows and database contention can still cost
time. Older schema-4 binaries reject schema 5; rollback requires a compatible
binary or a deliberately restored pre-upgrade backup, never lowering the version.
