package goauth

import (
	"context"
	"time"
)

// NotificationDelivery may be sent more than once before it is accepted,
// expires, or exhausts the attempt limit. A sender must use ID as its
// idempotency key when the underlying transport supports deduplication.
type NotificationDelivery struct {
	ID           string
	Notification Notification
	ValidUntil   time.Time
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
// outcome must wrap ErrOperationOutcomeUnknown. Nested calls join the same scope.
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
	return r.authTransaction.InAuthTransaction(ctx, fn)
}
