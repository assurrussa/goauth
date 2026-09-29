// Package authclock carries the Runtime clock across its transaction boundary.
// It is internal plumbing, not a source of authorization or caller credentials.
package authclock

import (
	"context"
	"time"
)

type contextKey struct{}

// With preserves the configured clock, including deterministic test clocks.
func With(ctx context.Context, now func() time.Time) context.Context {
	return context.WithValue(ctx, contextKey{}, now)
}

// Now must be called after acquiring locks, not before waiting for them.
// Direct store calls retain their supplied time origin but include elapsed wait.
func Now(ctx context.Context, origin, started time.Time) time.Time {
	if now, ok := ctx.Value(contextKey{}).(func() time.Time); ok && now != nil {
		return now().UTC()
	}
	return origin.Add(time.Since(started)).UTC()
}
