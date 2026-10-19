//nolint:testpackage // Verify historical notice routing through the private managed-queue currentness helper.
package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/assurrussa/goauth"
)

func TestRequestedEmailChangeNoticeRemainsCurrentWithoutLiveChallenge(t *testing.T) {
	// A nil database proves this historical, credential-free notice does not
	// depend on a pending challenge, current alias, confirmation or supersession.
	// Challenge code mail keeps its separate live-record checks.
	store := &Store{}
	for _, reference := range []string{"confirmed-request", "superseded-request", "deleted-request"} {
		current, err := store.notificationCurrent(context.Background(), goauth.EncryptedEvent{
			Type: "email_change_requested", ReferenceID: reference,
			ValidUntil: time.Now().Add(time.Hour),
		}, time.Now())
		if err != nil || !current {
			t.Fatalf("historical request notice suppressed: current=%v err=%v", current, err)
		}
	}
	current, err := store.notificationCurrent(context.Background(), goauth.EncryptedEvent{
		Type: "email_change_requested", ValidUntil: time.Now().Add(-time.Hour),
	}, time.Now())
	if err != nil || current {
		t.Fatalf("expired notice remains current: current=%v err=%v", current, err)
	}
}

