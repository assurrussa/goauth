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

// NotificationTransaction joins participating auth writes, encrypted enqueue,
// and audit writes in one transaction. PostgreSQL provides this for managed
// notification operations; it is not a general Runtime unit of work.
type NotificationTransaction interface {
	InNotificationTransaction(ctx context.Context, fn func(context.Context) error) error
}

type notificationMetadata struct {
	referenceID string
	validUntil  time.Time
}

func (r *Runtime) inNotificationTransaction(ctx context.Context, fn func(context.Context) error) error {
	if r.notificationTransaction == nil {
		return fn(ctx)
	}
	return r.notificationTransaction.InNotificationTransaction(ctx, fn)
}
