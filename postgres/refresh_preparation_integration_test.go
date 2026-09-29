//go:build integration

package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestPostgresRefreshPreparationExpiry(t *testing.T) {
	db := integrationDB(t)
	for _, tc := range []struct {
		name       string
		fraction   time.Duration
		refreshTTL time.Duration
		accessTTL  time.Duration
		sessionTTL time.Duration
		delay      time.Duration
		expired    bool
	}{
		{
			name: "short refresh TTL", refreshTTL: time.Second, accessTTL: 30 * time.Second,
			sessionTTL: time.Minute, delay: 2 * time.Second,
		},
		{
			name: "absolute session cap", refreshTTL: time.Minute, accessTTL: 30 * time.Second,
			sessionTTL: 10 * time.Second, delay: 2 * time.Second,
		},
		{
			name: "expired prepared access", refreshTTL: time.Second, accessTTL: 30 * time.Second,
			sessionTTL: time.Minute, delay: 30 * time.Second, expired: true,
		},
		{
			name: "JWT second precision", fraction: 250 * time.Millisecond, refreshTTL: time.Second,
			accessTTL: time.Second, sessionTTL: time.Minute, delay: 800 * time.Millisecond, expired: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			now := time.Now().UTC().Truncate(time.Second).Add(tc.fraction)
			config := runtimeConfig(t)
			config.Now = func() time.Time { return now }
			config.AccessTTL = tc.accessTTL
			config.SessionTTL = tc.sessionTTL
			config.RefreshTTL = time.Hour
			assembly := postgres.Config{DB: db, Runtime: config, NotificationSender: integrationNotificationSender()}
			runtime, err := postgres.NewRuntime(assembly)
			require.NoError(t, err)
			registered := register(t, runtime, "pg.slow.refresh@example.test")
			assembly.Runtime.RefreshTTL = tc.refreshTTL
			var slow bool
			assembly.Runtime.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
				context.Context, goauth.Realm, goauth.Account, map[string]any,
			) error {
				if slow {
					now = now.Add(tc.delay)
				}
				return nil
			})
			runtime, err = postgres.NewRuntime(assembly)
			require.NoError(t, err)
			slow = true
			rotated, err := runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			if tc.expired {
				require.ErrorIs(t, err, goauth.ErrExpiredToken)
				require.Empty(t, rotated.AccessToken)
				require.Empty(t, rotated.RefreshToken)
				var tokens, consumed int
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT count(*), count(consumed_at) FROM auth_refresh_tokens`).Scan(&tokens, &consumed))
				require.Equal(t, 1, tokens)
				require.Zero(t, consumed)
				slow = false
				rotated, err = runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			}
			require.NoError(t, err)
			expectedExpiry := now.Add(tc.refreshTTL)
			if expectedExpiry.After(registered.Tokens.Session.ExpiresAt) {
				expectedExpiry = registered.Tokens.Session.ExpiresAt
			}
			require.True(t, expectedExpiry.Equal(rotated.RefreshExpiresAt))
			parts := strings.Split(rotated.RefreshToken, ".")
			require.Len(t, parts, 3)
			var createdAt, expiresAt time.Time
			require.NoError(t, db.QueryRowContext(t.Context(),
				`SELECT created_at, expires_at FROM auth_refresh_tokens WHERE selector = $1`,
				parts[1]).Scan(&createdAt, &expiresAt))
			require.True(t, now.Equal(createdAt))
			require.True(t, expectedExpiry.Equal(expiresAt))
			require.True(t, expiresAt.After(createdAt), "committed replacement must have a positive remaining lifetime")
			_, err = runtime.AuthenticateSession(t.Context(), rotated.AccessToken)
			require.NoError(t, err)
			slow = false
			_, err = runtime.Refresh(t.Context(), rotated.RefreshToken)
			require.NoError(t, err, "the committed replacement must be usable")
			slow = true
			beforeReplay := now
			_, err = runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.ErrorIs(t, err, goauth.ErrRefreshReplay)
			require.Equal(t, beforeReplay, now, "authenticated replay must skip token preparation")
			var audits int
			require.NoError(t, db.QueryRowContext(t.Context(),
				`SELECT count(*) FROM auth_security_audit_events WHERE event_type = $1`,
				goauth.SecurityEventRefreshReplay).Scan(&audits))
			require.Equal(t, 1, audits)
		})
	}
}

func TestPostgresRefreshExpiredPreparationStillHandlesConcurrentReplay(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	now := time.Now().UTC().Truncate(time.Second)
	var runtime *postgres.Runtime
	var currentToken string
	var winner goauth.TokenPair
	var interleave bool
	config := runtimeConfig(t)
	config.Now = func() time.Time { return now }
	config.AccessTTL = 30 * time.Second
	config.SessionTTL = time.Minute
	config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
		ctx context.Context, _ goauth.Realm, _ goauth.Account, _ map[string]any,
	) error {
		if !interleave {
			return nil
		}
		interleave = false
		now = now.Add(29 * time.Second)
		var err error
		winner, err = runtime.Refresh(ctx, currentToken)
		now = now.Add(2 * time.Second)
		return err
	})
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	registered := register(t, runtime, "pg.expired.concurrent.replay@example.test")
	currentToken = registered.Tokens.RefreshToken
	interleave = true
	_, err = runtime.Refresh(t.Context(), currentToken)
	require.ErrorIs(t, err, goauth.ErrRefreshReplay)
	require.NotEmpty(t, winner.AccessToken)
	_, err = runtime.AuthenticateSession(t.Context(), winner.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	_, err = runtime.Refresh(t.Context(), winner.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	var audits int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM auth_security_audit_events WHERE event_type = $1`,
		goauth.SecurityEventRefreshReplay).Scan(&audits))
	require.Equal(t, 1, audits)
}
