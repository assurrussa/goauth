package goauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestRefreshRecomputesReplacementExpiryAfterPreparation(t *testing.T) {
	t.Parallel()
	for _, refreshTTL := range []time.Duration{time.Second, time.Minute} {
		t.Run(refreshTTL.String(), func(t *testing.T) {
			t.Parallel()
			now := time.Now().UTC().Truncate(time.Second)
			var config goauth.Config
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				c.Now = func() time.Time { return now }
				c.AccessTTL = 30 * time.Second
				c.SessionTTL = 10 * time.Second
				c.RefreshTTL = time.Hour
				config = *c
			})
			require.NoError(t, err)
			registered := registerAccount(t, fixture, "slow.refresh@example.test")
			config.RefreshTTL = refreshTTL
			var slow bool
			config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(context.Context, goauth.Realm, goauth.Account, map[string]any) error {
				if slow {
					now = now.Add(2 * time.Second)
				}
				return nil
			})
			fixture.Runtime, err = goauth.NewRuntime(config)
			require.NoError(t, err)
			slow = true
			rotated, err := fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.NoError(t, err)
			expectedExpiry := now.Add(refreshTTL)
			if expectedExpiry.After(registered.Tokens.Session.ExpiresAt) {
				expectedExpiry = registered.Tokens.Session.ExpiresAt
			}
			require.Equal(t, expectedExpiry, rotated.RefreshExpiresAt)
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), rotated.AccessToken)
			require.NoError(t, err)
			slow = false
			continued, err := fixture.Runtime.Refresh(t.Context(), rotated.RefreshToken)
			require.NoError(t, err, "replacement must be usable at the final rotation time")
			_, err = fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.ErrorIs(t, err, goauth.ErrRefreshReplay)
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), continued.AccessToken)
			require.ErrorIs(t, err, goauth.ErrSessionRevoked)
		})
	}
}

func TestRefreshExpiredPreparedAccessDoesNotConsumeToken(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		fraction  time.Duration
		accessTTL time.Duration
		delay     time.Duration
	}{
		{name: "expiry boundary", accessTTL: 30 * time.Second, delay: 30 * time.Second},
		{name: "past expiry", accessTTL: 30 * time.Second, delay: 31 * time.Second},
		{name: "JWT second precision", fraction: 250 * time.Millisecond, accessTTL: time.Second, delay: 800 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now := time.Now().UTC().Truncate(time.Second).Add(tc.fraction)
			var config goauth.Config
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				c.Now = func() time.Time { return now }
				c.AccessTTL = tc.accessTTL
				c.SessionTTL = time.Minute
				c.RefreshTTL = time.Hour
				config = *c
			})
			require.NoError(t, err)
			registered := registerAccount(t, fixture, "expired.preparation@example.test")
			var slow bool
			config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(context.Context, goauth.Realm, goauth.Account, map[string]any) error {
				if slow {
					now = now.Add(tc.delay)
				}
				return nil
			})
			fixture.Runtime, err = goauth.NewRuntime(config)
			require.NoError(t, err)
			slow = true
			tokens, err := fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.ErrorIs(t, err, goauth.ErrExpiredToken)
			require.Empty(t, tokens.AccessToken)
			require.Empty(t, tokens.RefreshToken)
			slow = false
			rotated, err := fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.NoError(t, err, "failed preparation must leave the current token unconsumed")
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), rotated.AccessToken)
			require.NoError(t, err)
		})
	}
}

func TestRefreshExpiredPreparationStillHandlesConcurrentReplay(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	var fixture *testkit.Fixture
	var currentToken string
	var winner goauth.TokenPair
	var interleave bool
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.Now = func() time.Time { return now }
		c.AccessTTL = 30 * time.Second
		c.SessionTTL = time.Minute
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			ctx context.Context, _ goauth.Realm, _ goauth.Account, _ map[string]any,
		) error {
			if !interleave {
				return nil
			}
			interleave = false
			now = now.Add(29 * time.Second)
			var err error
			winner, err = fixture.Runtime.Refresh(ctx, currentToken)
			now = now.Add(2 * time.Second)
			return err
		})
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "expired.concurrent.replay@example.test")
	currentToken = registered.Tokens.RefreshToken
	interleave = true
	_, err = fixture.Runtime.Refresh(t.Context(), currentToken)
	require.ErrorIs(t, err, goauth.ErrRefreshReplay)
	require.NotEmpty(t, winner.AccessToken)
	_, err = fixture.Runtime.AuthenticateSession(t.Context(), winner.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	_, err = fixture.Runtime.Refresh(t.Context(), winner.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

type delayedRefreshStore struct {
	goauth.RuntimeStore
	afterRotation func()
}

func (s *delayedRefreshStore) RotateRefresh(
	ctx context.Context, request goauth.RefreshRotationRequest,
) (goauth.RefreshRotationResult, error) {
	result, err := s.RuntimeStore.RotateRefresh(ctx, request)
	if err == nil && result.Status == goauth.RefreshRotationSucceeded {
		s.afterRotation()
	}
	return result, err
}

func TestRefreshRotationLatencyRollsBackExpiredPair(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		accessTTL  time.Duration
		refreshTTL time.Duration
	}{
		{name: "access expiry", accessTTL: time.Second, refreshTTL: time.Minute},
		{name: "refresh expiry", accessTTL: 30 * time.Second, refreshTTL: time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			now := time.Now().UTC().Truncate(time.Second)
			var delay time.Duration
			var config goauth.Config
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				c.Now = func() time.Time { return now }
				c.AccessTTL = tc.accessTTL
				c.SessionTTL = time.Minute
				c.RefreshTTL = time.Hour
				c.Store = &delayedRefreshStore{RuntimeStore: c.Store, afterRotation: func() { now = now.Add(delay) }}
				config = *c
			})
			require.NoError(t, err)
			registered := registerAccount(t, fixture, "slow.rotation@example.test")
			config.RefreshTTL = tc.refreshTTL
			fixture.Runtime, err = goauth.NewRuntime(config)
			require.NoError(t, err)
			delay = 2 * time.Second
			tokens, err := fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.ErrorIs(t, err, goauth.ErrExpiredToken)
			require.Empty(t, tokens.AccessToken)
			require.Empty(t, tokens.RefreshToken)
			delay = 0
			rotated, err := fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.NoError(t, err, "expired rotation must roll back consumption")
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), rotated.AccessToken)
			require.NoError(t, err)
		})
	}
}
