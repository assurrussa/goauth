# Production notification delivery

GoAuth stays provider-neutral. A host supplies a
`goauth.NotificationSender` to `postgres.Config.NotificationSender`; GoAuth
does not configure SMTP, depend on GoNotify, or select a provider. The
[net/http example](../examples/nethttp/README.md) deliberately keeps its
loopback-only SMTP catcher for local development. It is not production mail
wiring.

## Managed queue contract

- Auth state, mandatory audit, and the native encrypted notification event
  commit in one PostgreSQL transaction. Send from the supervised
  `auth.RunNotifications(ctx)` worker, never from the auth transaction hook.
- `NotificationDelivery.ID` is the stable opaque operation identity. Repeated
  delivery attempts keep that ID and the original `ValidUntil`; the managed
  worker supplies the matching `EncryptedEvent.ID` and
  `EncryptedEvent.ValidUntil`.
- Treat `ValidUntil` as an exclusive absolute deadline. Do not rebuild it from
  `Notification.Data["expires"]`, `time.Now() + TTL`, or envelope retention.
  Retention controls encrypted storage lifetime, not credential validity.
- `Notification` is plaintext available for the current attempt only. Never
  persist its codes, reset URLs, or rendered content in an ordinary mail queue,
  generic outbox, dead-letter payload, or logs. An additional host durable
  transport may carry the original `EncryptedEvent`
  only, preserving identity, expiry and stale-auth-state checks. An explicitly
  configured encrypted gateway is a separate ownership/retention boundary; use
  the queued contract below, never an ordinary host plaintext job.
- For the direct provider adapter described below, return `nil` only after
  confirmed provider acceptance. An HTTP response, queue admission, or local
  enqueue alone is insufficient. Acceptance does not prove inbox delivery.
  GoAuth delivery is at least once, not exactly once.
  For durable queue ownership, use the explicit NotificationQueuedError contract below.
  Queue acceptance is never returned as nil.

The worker rechecks current one-time state before sending. A concurrent account
change during external dispatch can still reach the provider; the Runtime
validates token/code state again when the recipient uses it. Retain old
notification encryption keys until their queued events no longer need them.

## Optional host adapter: NotifyHub

Keep this integration in the consuming application's module; GoAuth remains
provider-neutral and has no GoNotify dependency. Use a reviewed compatible
GoNotify release exposing high priority and a schema15-compatible GoAuth release.
The local source candidate is not a published-module installation result. Do not
invent or select an unreleased tag in a production app manifest.

Reuse one `notifyhub.Client` with the gateway origin/deployment prefix, existing
project credential and bounded timeout. HTTPS is required outside isolated
loopback tests; secrets and proxy/APM request bodies must not enter logs. Provider
credentials and selection remain owned by Hub.

The retired `POST /v1/confidential-email` returns 410. New security mail uses the
explicitly authorized **encrypted** durable Hub queue via `/v1/notifications`,
with high priority and the original absolute expiry. Do not put plaintext tokens
in a host generic outbox, DLQ, diagnostic record or fallback transport.

The host sender implements the existing `NotificationSender` plus
`NotificationTransportProtocol` and `NotificationReconciler`:

- Protocol is `notifyhub_queue_v1`. Only new managed events snapshot it. Old
  protocol-empty events are held before dispatch; do not bulk restamp them.
- Render deterministically from the sealed notification. Keep From, rendering,
  project, event, original expiry and idempotency namespace stable while pending.
  A lost response retries only that same immutable request and key.
- Validate a successful Submit receipt and return `NotificationQueuedError{ReceiptID}`
  even if a duplicate already reports accepted. Native ownership must be persisted
  and its encrypted copy scrubbed before metadata-only reconciliation.
- Reconcile only by Get of that same receipt. Explicit accepted/delivered returns
  nil. Pending, unknown, bounce/complaint and future statuses retain ownership;
  no status grants a new key or fallback. Terminal failure uses the separate
  `ErrNotificationQueueFailed`, never a claim that no prior handoff occurred.

Historical confidential receipts remain diagnostics and fence their original
keys in the new queue. Classify accepted, explicitly not-sent and unknown old
operations before cutover. Old bodies are not automatically migrated. Preserve
old provider evidence and never bypass a fence by renaming the key. An older
synchronous sender still uses nil only after provider acceptance, not queue202.

## Synchronous legacy outcomes and initial submission failures

Only a nil SDK error with `StatusAccepted` confirms provider handoff. In
particular, `simulated`, `dispatching`, and `unknown` are not success.

- `OutcomeRetryable` means Hub explicitly confirmed a temporary rejection.
  Retry only the identical key, event, email content, and original expiry.
- `OutcomeUnknown` includes in-flight dispatch, ambiguous network failures,
  timeouts, and untrusted responses. The provider may have accepted the mail.
  An identical request can reconcile Hub's metadata; a stored unknown must not
  redispatch. Never create a new key, reissue a credential, revoke a valid
  credential, or fall back to another transport merely because of this result.
- `OutcomeRejected` is terminal provider rejection. `OutcomeSimulated` is
  dry-run without real handoff. Map only these positively known terminal
  non-delivery outcomes to `goauth.ErrNotificationRejected`. The managed worker
  stops retries, records `exhausted` / `sender_rejected`, scrubs the envelope,
  and leaves `delivered_at` NULL. Never return nil for either outcome.
- `OutcomeNotSent` covers validation, expiry,
  pre-I/O cancellation, and definitive pre-admission rejection. Fix invalid
  configuration or authorization rather than creating a replacement operation.
- An idempotency conflict means the operation changed under its key. Investigate
  renderer/configuration drift; do not work around it with a new key.

The managed GoAuth worker recognizes `goauth.ErrNotificationRejected` (including
wrapped errors) as an explicit terminal non-delivery disposition. Before durable queue ownership, ordinary non-nil sender errors retain configured
backoff, attempt limit and expiry. `NotificationQueuedError` and subsequent receipt
reconciliation are explicit exceptions; `ErrNotificationQueueFailed` is a separate
terminal downstream disposition, not synchronous rejection.
Never map `OutcomeRetryable`, `OutcomeUnknown`, a timeout, cancellation, or a
lost/untrusted response to this sentinel. The worker does not itself interpret
GoNotify's outcomes or `RetryAfter`. The current worker cannot honor a dynamic
per-delivery retry deadline without explicit worker support. Do not implement a
sender-side not-before gate that simply returns an error: the worker reserves
and increments an attempt before calling the sender, so each gated call still
consumes the attempt budget and can exhaust it before the delay ends. Any delay
inside the sender must honor its context, whose deadline is bounded by
`SendTimeout` and the original expiry.
Configure the native `RetryMin`, `RetryMax`, and `MaxAttempts` conservatively for
the provider's expected delays and credential validity; longer provider delays
may still outlast that budget. Record terminal/unknown outcomes for operators
without acknowledging them as accepted.
Adapters do not run an alternate transport or invent a retry identity. Before
ownership, an ordinary error can lead to another identical Submit. After ownership,
only Get is permitted; observation errors do not use the send-attempt budget.
Terminal queue disposition stops observation without authorizing replacement mail.

## Production checks and operations

- Test real provider acceptance separately from Hub dry-run. Exercise duplicate
  accepted requests, explicit temporary rejection, unknown/dispatching,
  simulation, expiry, cancellation, idempotency conflict, and renderer failure.
  Verify repeated attempts preserve ID, payload, and original expiry.
- Keep codes, auth URLs, bodies, recipients, credentials, and arbitrary provider
  errors out of host/Hub/proxy logs and traces. Use delivery ID and bounded
  machine outcomes; never put a secret in an event name or idempotency key.
- Supervise and join `RunNotifications`; honor context cancellation, schedule
  queue-only `auth.ExpireNotifications(ctx, limit)` under a bounded host timeout
  when only notification expiry is intended (see [outcome and expiry semantics](notification-outcomes.md));
  use broad `auth.Cleanup` only with an explicit host retention policy. Monitor `NotificationStats` plus
  `NotificationWorkerConfig.OnBlocked`. Alert on exhausted, expired, blocked,
  simulated, and unresolved unknown deliveries without logging their payloads.
- For rollout or rollback, stop and join the old worker before switching senders.
  Preserve the encrypted queue, key rings, delivery IDs, and original deadlines.
  Keep pending operations on the same Hub project and idempotency namespace;
  switching an uncertain operation to SMTP or another gateway risks duplicates.
  A missing or incompatible queue endpoint must fail closed. Historical confidential
  operations remain fenced and are not silently replayed into it.

## Operator lifecycle controls

Schema 12 adds transaction-aware `CancelNotification` and bounded,
queue-only `CleanupNotificationReceipts`. See [notification lifecycle](notification-lifecycle.md)
for eligibility, lease fencing, conservative receipt retention and the required
future-only interpretation of cancellation.

## Safe sender diagnostics (schema 13)

Senders may optionally return an error implementing `goauth.NotificationDiagnosticError`.
Its `NotificationDiagnostic()` result contains only `Outcome`, `Code`, and an
`HTTPStatus` (zero when no response was observed). This is source-compatible with
existing senders. PostgreSQL independently rejects unknown strings, contradictory
outcome/code/status combinations, and a terminal outcome without
`errors.Is(err, goauth.ErrNotificationRejected)` (or a nonterminal outcome with
that sentinel). Never put addresses, tokens, URLs, response bodies or raw errors
in these fields. Unknown or unsupported diagnostics are omitted entirely.

For a valid sender failure, the worker persists `last_sender_outcome`,
`last_sender_code`, `last_sender_http_status`, `last_sender_attempt` and
`last_sender_observed_at` in the same lease-token-checked statement as queue
settlement. The attempt number comes from the reserved database counter. A late
completion cannot overwrite a newer lease or expired row. New send reservations,
accepted sends, non-sender settlement, cancellation and expiry clear these fields.
Legacy rows and legacy sender errors have all five fields NULL. There is no
backfill, extra send, retry-policy change or delivery confirmation.

Allowed outcomes are `not_sent`, `retryable`, `unknown`, `rejected`, and
`simulated`. Admission errors use their exact status (`unauthorized`: 401/403,
`endpoint_unavailable`: 404/405, `quota_exceeded`: 429, `request_too_large`: 413,
`idempotency_conflict`: 409). Local validation/cancellation/expiry use zero;
`invalid_request` also permits 400 and `expired` permits 410. Unknown network
failure is `request_failed`/zero, dispatching is 202, and ambiguous dispatch is
409. `invalid_response` permits HTTP statuses 100–599 except definitive admission
statuses. Temporary rejection is 503; terminal rejection is 422; simulation is
200. Only fixed documented codes are accepted. Diagnostics describe one attempt,
not the overall delivery result: a retry or earlier ambiguous outcome can still
have reached the provider. Hosts must not infer inbox delivery or reissue secrets
from these fields. Hosts should show unavailable for NULL diagnostics.

## NotifyHub managed queue ownership (candidate schema 15)

The retired `/v1/confidential-email` route returns 410. New integrations use
`POST /v1/notifications` with high priority and the **original absolute** expiry.
The HTTP 202 response transfers durable queue ownership; it is not provider
acceptance. Historical synchronous adapters are not a migration recipe.

A sender returns `&goauth.NotificationQueuedError{ReceiptID: receipt.ID}` after a valid
Submit receipt and implements `NotificationReconciler`. GoAuth atomically stores
that bounded opaque receipt, sets `gateway_accepted`, leaves `delivered_at` NULL,
and scrubs ciphertext/nonce/additional data. This reduces secret copies: the
explicitly authorized encrypted NotifyHub queue now owns the content. No local
plaintext copy, fallback transport, or new notification is created.

The existing worker reconciles using metadata-only `NotificationQueueReceipt`
(ID, ReceiptID, original ValidUntil). Get the existing gateway receipt; do not
resubmit. Return nil only for explicit provider accepted/delivered. Pending and
unknown remain queue-owned; observation failures do not spend the send budget.
The synchronous `ErrNotificationRejected` sentinel cannot retroactively prove
non-acceptance after queue ownership and is treated as an observation failure.
Late nil responses after the observation timeout do not acknowledge success;
the original absolute deadline still closes reconciliation.
Terminal downstream failed/expired/suppressed results return ErrNotificationQueueFailed,
which does not claim that no earlier provider handoff occurred. Simulated means
no real mail, but is likewise terminal; never create a replacement automatically.
An unavailable reconciler never triggers another submit. Expiry closes further
observation and preserves a non-delivery-claiming receipt; it cannot recall an
already in-flight message. Cancellation is unsupported after ownership transfer.

Rollout requires the additive schema migration and compatible app senders before
workers restart. Existing synchronous receipts must retain their old semantics;
never replay an unknown legacy operation into the new queue. Release, migration
execution, deployment and any legacy-receipt transition require separate review.

### Protocol fence and rollback

A queue sender implements `NotificationTransportProtocol() string` and returns
`notifyhub_queue_v1`. New native rows snapshot it at enqueue. Pre-cutover rows
remain empty, and the worker blocks any protocol mismatch before decryption or
send, without spending send attempts. Do not bulk stamp old rows with the new
protocol. Reconcile historical accepted, explicitly not-sent, and unknown Hub
receipts first; historical keys are fenced in NotifyHub's new queue. Never
rename a key to bypass that fence. Old synchronous senders which do not implement
the optional interface retain their existing empty protocol behavior.

Deploying an older binary after schema 15 is not a rollback: it must refuse the
future schema and cannot safely reinterpret scrubbed gateway-owned rows. Stop
workers and retain this compatible reconciler; queue-owned data survives. Any
manual legacy disposition or reissuance must be independently justified by its
provider evidence and original credential expiry.


### Metadata-only historical provider proof

Hosts with durable historical receipts may implement the optional
`LegacyNotificationReconciler`. It receives only the original event ID, empty
legacy protocol marker and original deadline, before any decryption or send.
Return nil only when the exact operation has independently verified provider
acceptance. Admission, consumption, unrelated receipts and unknown or conflicting
outcomes are not proof. Any error keeps the operation fenced; this hook must not
send, render, decrypt, replace keys or write canonical delivery rows.

The worker holds the subject lock, checks current credential/subject policy,
and completes through its own protocol/lease/deadline CAS. Proven acceptance
scrubs the local encrypted payload without reserving a new send attempt.
Expired, revoked, reclaimed or nonlegacy operations cannot be revived. Hosts
without reliable positive evidence leave the optional hook unimplemented.
