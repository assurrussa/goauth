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
  generic outbox, dead-letter payload, or logs. An additional durable transport
  may carry the original `EncryptedEvent` only; its consumer must preserve
  identity, expiry, and stale-auth-state checks before provider dispatch.
- For the direct provider adapter described below, return `nil` only after
  confirmed provider acceptance. An HTTP response, queue admission, or local
  enqueue alone is insufficient. Acceptance does not prove inbox delivery.
  GoAuth delivery is at least once, not exactly once.

The worker rechecks current one-time state before sending. A concurrent account
change during external dispatch can still reach the provider; the Runtime
validates token/code state again when the recipient uses it. Retain old
notification encryption keys until their queued events no longer need them.

## Optional host adapter: NotifyHub

Keep this integration in the consuming application's module. Its verified
GoNotify SDK pin is:

```sh
# Run in the host application's module, not in GoAuth.
go get github.com/assurrussa/gonotify@v0.5.1-0.20261003102326-7b5e3c74da5d
```

The contract references are [GoNotify confidential email at 7b5e3c74da5d](https://github.com/assurrussa/gonotify/blob/7b5e3c74da5d4404a6b0b507cf46fd7f0ebc20f3/docs/confidential-email.md)
and [NotifyHub at 8013fbf8ab0b](https://github.com/assurrussa/notifyhub/blob/8013fbf8ab0b14b660316f5cb64aae4e14b674f9/README.md#confidential-auth-email).
Verify that the deployed Hub includes the confidential endpoint; an SDK pin
alone does not upgrade the server or establish production readiness.

Construct one `*notifyhub.Client` with `notifyhub.New` at host startup and reuse
it for ordinary notifications and auth mail. Use the same gateway origin or
deployment prefix (`Config.BaseURL`), project credential (`Config.ProjectKey`),
and bounded `Config.Timeout`. Use HTTPS outside isolated loopback tests; leave
`AllowInsecureHTTP` false. Keep the project credential outside source and logs.
Provider credentials and provider selection belong to Hub, not the GoAuth host.

Ordinary non-secret messages may use GoNotify's ordinary delivery path. Auth
codes and reset links must use `Client.SendConfidentialEmail`, which performs
one synchronous `POST /v1/confidential-email`. Never pass these secrets through
ordinary `Send`/`Submit`, `/v1/notifications`, Hub SMTP ingress, a generic outbox,
or fallback SMTP. The confidential route stores outcome metadata and a protected
payload fingerprint in Hub, not the recipient, message body, code, or auth URL.
The GoAuth queue remains the encrypted durable owner of the auth payload.
TLS, reverse-proxy/APM body logging, and the external email provider's retention
must also be reviewed; the endpoint does not control those systems.

This host-owned adapter sketch uses an already initialized shared client. The
host's `render` function must support the GoAuth templates it enables and return
the same subject and text for the same notification on every attempt. It must
not mutate the notification or log its contents. Keep the sender address, event,
key namespace, and rendering stable across deployments while deliveries remain
pending; changed content under an existing key must fail closed. The sketch
routes every GoAuth notification through the confidential path, including
credential-free security notices.

```go
package hostmail

import (
	"context"
	"errors"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/gonotify/transport"
	"github.com/assurrussa/gonotify/transport/notifyhub"
)

func AuthSender(
	hub *notifyhub.Client,
	from string,
	render func(goauth.Notification) (subject, text string, err error),
) goauth.NotificationSender {
	return goauth.NotificationSenderFunc(func(ctx context.Context, delivery goauth.NotificationDelivery) error {
		if hub == nil || render == nil || delivery.ID == "" || delivery.ValidUntil.IsZero() {
			return errors.New("auth mail configuration or delivery is invalid")
		}
		subject, text, err := render(delivery.Notification)
		if err != nil {
			return errors.New("auth mail rendering failed") // Do not expose raw renderer errors.
		}
		receipt, err := hub.SendConfidentialEmail(ctx, notifyhub.ConfidentialEmailRequest{
			IdempotencyKey: "myapp:auth:" + delivery.ID,
			Event:          "myapp.auth",
			ExpiresAt:      delivery.ValidUntil,
			Email: transport.EmailMessage{
				From: from, To: []string{delivery.Notification.To}, Subject: subject, Text: text,
			},
		})
		if err != nil {
			return err // This pinned SDK returns bounded, sanitized confidential errors.
		}
		if receipt.Status != notifyhub.StatusAccepted {
			return notifyhub.ErrConfidentialOutcomeUnknown
		}
		return nil
	})
}
```

Pass the returned sender to `postgres.Config.NotificationSender`. The client
bounds each call by the earliest of the caller's context, configured timeout,
and original expiry. It floors expiry to Unix seconds, never extending it; the
wire cutoff may be less than one second earlier. Hub allows expiry at most seven
days ahead, so validate compatible host lifetimes before enabling this route.
Use a deterministic, non-sensitive key prefix for the application, never an
email address, reset token, or code. Do not generate a key inside a retry.

## Outcomes and retries

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
  dry-run without real handoff. `OutcomeNotSent` covers validation, expiry,
  pre-I/O cancellation, and definitive pre-admission rejection. Fix invalid
  configuration or authorization rather than creating a replacement operation.
- An idempotency conflict means the operation changed under its key. Investigate
  renderer/configuration drift; do not work around it with a new key.

The managed GoAuth worker treats every non-nil sender error as unsuccessful and
applies its configured backoff, attempt limit, and expiry. It does not interpret
GoNotify's outcomes or `RetryAfter`. A production host should add a metadata-only
per-ID not-before gate when `RetryAfter` exceeds the native backoff, and record
terminal/unknown outcomes for operators without acknowledging them as accepted.
The sketch deliberately has no retry loop or alternate transport. Returning an
error can lead to another identical worker attempt; Hub's retained outcome
prevents a terminal or ambiguous operation from being blindly redispatched.

## Production checks and operations

- Test real provider acceptance separately from Hub dry-run. Exercise duplicate
  accepted requests, explicit temporary rejection, unknown/dispatching,
  simulation, expiry, cancellation, idempotency conflict, and renderer failure.
  Verify repeated attempts preserve ID, payload, and original expiry.
- Keep codes, auth URLs, bodies, recipients, credentials, and arbitrary provider
  errors out of host/Hub/proxy logs and traces. Use delivery ID and bounded
  machine outcomes; never put a secret in an event name or idempotency key.
- Supervise and join `RunNotifications`; honor context cancellation, schedule
  `auth.Cleanup`, and monitor `NotificationStats` plus
  `NotificationWorkerConfig.OnBlocked`. Alert on exhausted, expired, blocked,
  simulated, and unresolved unknown deliveries without logging their payloads.
- For rollout or rollback, stop and join the old worker before switching senders.
  Preserve the encrypted queue, key rings, delivery IDs, and original deadlines.
  Keep pending operations on the same Hub project and idempotency namespace;
  switching an uncertain operation to SMTP or another gateway risks duplicates.
  A missing or incompatible confidential endpoint must fail closed.
