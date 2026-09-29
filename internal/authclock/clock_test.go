package authclock

import (
	"context"
	"testing"
	"time"
)

func TestCurrentClockIsReadAfterWait(t *testing.T) {
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := origin
	ctx := With(context.Background(), func() time.Time { return now })
	now = now.Add(time.Hour)
	if got := Now(ctx, origin, time.Now()); !got.Equal(now) {
		t.Fatalf("got %v, want current clock %v", got, now)
	}
}

func TestDirectStoreTimeIncludesElapsedWait(t *testing.T) {
	origin := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	started := time.Now().Add(-time.Hour)
	if got := Now(context.Background(), origin, started); got.Before(origin.Add(time.Hour)) {
		t.Fatalf("elapsed wait was lost: %v", got)
	}
}
