package authclock_test

import (
	"testing"
	"time"

	"github.com/assurrussa/goauth/internal/authclock"
)

func TestCurrentClockIsReadAfterWait(t *testing.T) {
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := origin
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	now = now.Add(time.Hour)
	if got := authclock.Now(ctx, origin, time.Now()); !got.Equal(now) {
		t.Fatalf("got %v, want current clock %v", got, now)
	}
}

func TestDirectStoreTimeIncludesElapsedWait(t *testing.T) {
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	started := time.Now().Add(-time.Hour)
	if got := authclock.Now(t.Context(), origin, started); got.Before(origin.Add(time.Hour)) {
		t.Fatalf("elapsed wait was lost: %v", got)
	}
}
