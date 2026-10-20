# Requested email-change security notice

The additive trusted-host method
`Runtime.RequestEmailChangeWithPreviousEmailNotice(ctx, subjectID, newEmail, previousEmail)`
opts one issuance into a credential-free old-mailbox notice. Existing
`RequestEmailChange` and password/HTTP APIs retain their behavior. Empty
`previousEmail` retains the original issuance behavior.

Like the original trusted API, hosts must authorize the actor and require fresh
authentication. For a scoped host projection, the host must read and validate
mailbox ownership under its existing canonical subject transaction, then pass
only the verified canonical old address. It must not take this argument from a
browser form. The Runtime normalizes and exactly compares it to the snapshot
captured under the subject lock. A missing or mismatched snapshot fails closed.
The unscoped primary-email path independently requires a verified primary email.

Only EmailChangeIssued queues `email_change_requested`, atomically with challenge
issuance, the new-mailbox code event and mandatory audit. Same-value,
rate-limited and other denied issuance queues no notice. Any enqueue/audit
failure rolls back all participating writes. No external send occurs here.

The encrypted notification has Template `email_change_requested`, captured
previous recipient, and optional trusted `email_change_scope` only. It contains
no confirmation code, token, new address or authentication link. A host sender
must support this template before adopting the new method.

The event records the issuance ID for correlation but uses the normal security
notification envelope-retention deadline, not the short challenge deadline.
It is a historical notice that a change was requested. Confirmation,
supersession or removal of the pending challenge must not suppress it. Its
wording must not claim the change remains pending when delivered. Existing
`email_changed` remains the separate completed-stage notice.

Managed delivery remains at-least-once with a stable persisted delivery UUID.
Use that UUID as downstream idempotency key. Retry, terminal rejection,
encrypted-payload scrubbing, expiry, cancellation and receipt cleanup retain
the existing worker semantics. This is not exactly-once caller-request
semantics: an unknown commit is not a rollback and must not be blindly replayed.
A later independently admitted issuance legitimately creates a new notice.

No database migration, new queue, new supported package, Runtime configuration
flag, live notification preference lookup or generic arbitrary-event API is added.

