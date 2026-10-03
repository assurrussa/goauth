package goauth

import (
	"context"
	"errors"
	"time"
)

// ErrNotificationRejected is an explicit terminal non-delivery disposition from a
// NotificationSender. Return it, optionally wrapped, only when the transport has
// definitively rejected or simulated the operation without accepting real mail.
// Never use it for timeouts, lost responses or unknown provider outcomes.
// PostgreSQL records an unsuccessful terminal receipt (exhausted/sender_rejected),
// scrubs the envelope, and leaves delivered_at NULL. Ordinary errors keep retrying.
var ErrNotificationRejected = errors.New("notification permanently rejected")

// NotificationDelivery may be sent more than once before it is accepted,
// expires, or exhausts the attempt limit. A sender must use ID as its
// idempotency key when the underlying transport supports deduplication.
type NotificationDelivery struct {
	ID string
	// EncryptedEvent is the exact sealed event claimed by the managed worker.
	// Delivery transports may persist this envelope, but never Notification's
	// plaintext codes/tokens. Use ID for downstream idempotency; delivery is at-least-once.
	EncryptedEvent EncryptedEvent
	Notification   Notification
	ValidUntil     time.Time
}

// NotificationSender is the only delivery integration required from a host
// using the PostgreSQL managed notification queue.
type NotificationSender interface {
	SendNotification(ctx context.Context, delivery NotificationDelivery) error
}

type NotificationSenderFunc func(context.Context, NotificationDelivery) error

func (f NotificationSenderFunc) SendNotification(ctx context.Context, delivery NotificationDelivery) error {
	return f(ctx, delivery)
}

// AuthTransaction atomically commits all participating auth, audit and encrypted
// event writes. Callback errors roll back. A failed commit with uncertain server
// outcome must wrap ErrOperationOutcomeUnknown. Nested auth writes join the same
// scope. Credential-attempt admission is separate: built-in stores reject
// TakeRateLimit in this scope with ErrRateLimitTransactionUnsupported. Call
// rate-limited Runtime operations outside an outer transaction.
// Hooks must not perform irreversible external actions inside this callback.
type AuthTransaction interface {
	InAuthTransaction(ctx context.Context, fn func(context.Context) error) error
}

// NotificationTransaction is the previous notification-only contract.
//
// Deprecated: implement AuthTransaction for every Runtime operation.
type NotificationTransaction interface {
	InNotificationTransaction(ctx context.Context, fn func(context.Context) error) error
}

type notificationMetadata struct {
	referenceID string
	validUntil  time.Time
}

func (r *Runtime) inNotificationTransaction(ctx context.Context, fn func(context.Context) error) error {
	return r.inSecurityTransaction(ctx, fn)
}
