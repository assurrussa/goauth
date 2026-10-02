package goauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/testkit"
)

type clockCheckingRefreshStore struct {
	goauth.RuntimeStore
	check func(context.Context)
}

func (s *clockCheckingRefreshStore) PeekRefresh(
	ctx context.Context, request goauth.RefreshRotationRequest,
) (goauth.RefreshRotationResult, error) {
	s.check(ctx)
	return s.RuntimeStore.PeekRefresh(ctx, request)
}

func (s *clockCheckingRefreshStore) RotateRefresh(
	ctx context.Context, request goauth.RefreshRotationRequest,
) (goauth.RefreshRotationResult, error) {
	s.check(ctx)
	return s.RuntimeStore.RotateRefresh(ctx, request)
}

func TestRefreshPropagatesConfiguredClockToStorage(t *testing.T) {
	t.Parallel()
	now := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	checks := 0
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.Now = func() time.Time { return now }
		c.Store = &clockCheckingRefreshStore{RuntimeStore: c.Store, check: func(ctx context.Context) {
			checks++
			require.Equal(t, now, authclock.Now(ctx, time.Time{}, time.Now()))
		}}
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "clock.refresh@example.test")
	_, err = fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, 2, checks, "both snapshot and rotation must receive the configured clock")
}
