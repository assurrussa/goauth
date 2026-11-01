package goauth

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrNotificationQueueFailed is a terminal downstream queue disposition after
// durable ownership. It does not prove that no prior provider handoff occurred.
// Never use it to authorize a replacement message, key, or fallback transport.
// The managed worker records exhausted/gateway_failed, not delivered or the
// synchronous sender_rejected non-acceptance disposition.
var ErrNotificationQueueFailed = errors.New("downstream notification queue terminated without confirmed provider acceptance")

// NotificationQueueReceipt identifies durable downstream ownership. It contains
// metadata only: never addresses, message text, credentials, or provider errors.
// ID and ValidUntil are the original managed delivery identity and deadline.
type NotificationQueueReceipt struct {
	ID         string
	ReceiptID  string
	ValidUntil time.Time
}

// NotificationQueuedError reports durable gateway ownership, NOT provider acceptance.
// The managed worker atomically saves ReceiptID and scrubs its encrypted payload.
// Return only after the gateway has durably accepted the immutable request.
// Subsequent attempts use NotificationReconciler, never SendNotification again.
type NotificationQueuedError struct{ ReceiptID string }

func (e *NotificationQueuedError) Error() string { return "notification accepted by downstream queue" }

// NotificationReconciler observes a previously accepted receipt without sending
// another message. Nil retains the legacy provider-acceptance meaning. Return
// NotificationQueuedError with the SAME receipt while pending or unknown; ordinary
// errors also keep reconciling, without spending the send-attempt budget.
// ErrNotificationRejected is synchronous-only and cannot revoke queue ownership.
// A timed-out observation cannot acknowledge success; the original absolute
// deadline still closes observation even if a reconciler returns a late nil.
// ErrNotificationQueueFailed reports a terminal downstream failure without
// claiming that a provider never accepted the operation.
type NotificationReconciler interface {
	ReconcileNotification(ctx context.Context, receipt NotificationQueueReceipt) error
}

// NotificationQueueReceiptID validates bounded, opaque metadata returned through
// a wrapped NotificationQueuedError. It never copies an invalid identifier to errors.
func NotificationQueueReceiptID(err error) (string, bool) {
	var queued *NotificationQueuedError
	if !errors.As(err, &queued) || queued == nil {
		return "", false
	}
	id := queued.ReceiptID
	if len(id) == 0 || len(id) > 128 || strings.TrimSpace(id) != id {
		return "", false
	}
	for _, c := range id {
		if !notificationReceiptRuneAllowed(c) {
			return "", false
		}
	}
	return id, true
}

// NotificationTransportProtocol selects an immutable dispatch protocol for NEW
// managed events. Changing it fences existing events for explicit reconciliation;
// it never reinterprets previously attempted deliveries as new queue operations.
// Empty retains the legacy protocol. Nonempty values are bounded opaque machine
// identifiers, not secrets or addresses.
type NotificationTransportProtocol interface{ NotificationTransportProtocol() string }

func notificationReceiptRuneAllowed(value rune) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' ||
		value == '-' || value == '_' || value == ':' || value == '.'
}

// LegacyNotificationReceipt contains only the immutable identity of a fenced
// historical operation. It never grants permission to resend or decrypt it.
type LegacyNotificationReceipt struct {
	ID                string
	TransportProtocol string
	ValidUntil        time.Time
}

// LegacyNotificationReconciler is an optional, read-only migration observer.
// Nil means verified provider acceptance for this exact historical event, not
// queue admission, consumption, or an unknown outcome. Any error retains the
// protocol fence. Implementations must never render, decrypt, send, or mutate
// the canonical delivery queue. The worker owns completion and its lease CAS.
type LegacyNotificationReconciler interface {
	ReconcileLegacyNotification(ctx context.Context, receipt LegacyNotificationReceipt) error
}
