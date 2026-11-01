package goauth_test

import (
	"fmt"
	"testing"

	"github.com/assurrussa/goauth"
)

func TestNotificationQueueReceiptIdentity(t *testing.T) {
	for _, id := range []string{"receipt-1", "00000000-0000-0000-0000-000000000001"} {
		got, ok := goauth.NotificationQueueReceiptID(fmt.Errorf("wrapped: %w", &goauth.NotificationQueuedError{ReceiptID: id}))
		if !ok || got != id {
			t.Fatal("valid receipt lost")
		}
	}
	for _, id := range []string{"", "address@example.test", "secret\nvalue", " receipt", "https://secret.test/path"} {
		if _, ok := goauth.NotificationQueueReceiptID(&goauth.NotificationQueuedError{ReceiptID: id}); ok {
			t.Fatal("invalid receipt accepted")
		}
	}
	var nilReceipt *goauth.NotificationQueuedError
	if _, ok := goauth.NotificationQueueReceiptID(nilReceipt); ok {
		t.Fatal("nil receipt accepted")
	}
}
