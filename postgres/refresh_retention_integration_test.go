//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func refreshRetentionRuntime(t *testing.T, sessionTTL, refreshTTL time.Duration) (*postgres.Runtime, *sql.DB, *atomic.Int64) {
	t.Helper()
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	clock := &atomic.Int64{}
	clock.Store(time.Now().UTC().Truncate(time.Second).UnixNano())
	config := runtimeConfig(t)
	config.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	config.SessionTTL, config.RefreshTTL = sessionTTL, refreshTTL
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	return runtime, db, clock
}

func retentionCleanup(t *testing.T, runtime *postgres.Runtime, clock *atomic.Int64, retention time.Duration) postgres.CleanupResult {
	t.Helper()
	result, err := runtime.Cleanup(t.Context(), postgres.CleanupPolicy{
		ExpiredRecordRetention: retention,
		Now:                    func() time.Time { return time.Unix(0, clock.Load()).UTC() },
	})
	require.NoError(t, err)
	return result
}

func TestPostgresCleanupPreservesRefreshReplayEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sessionTTL time.Duration
		refreshTTL time.Duration
		retention  time.Duration
		advance    time.Duration
	}{
		{"defaults", 0, 0, 0, 25 * time.Hour},
		{"custom short token", 60 * 24 * time.Hour, 2 * time.Hour, time.Hour, 4 * time.Hour},
		{"custom long session", 90 * 24 * time.Hour, 60 * 24 * time.Hour, time.Hour, 45 * 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initialRefreshTTL := tc.refreshTTL
			if tc.name == "custom short token" {
				initialRefreshTTL = tc.sessionTTL
			}
			runtime, db, clock := refreshRetentionRuntime(t, tc.sessionTTL, initialRefreshTTL)
			registered := register(t, runtime, "retention@example.test")
			original := registered.Tokens.RefreshToken
			if tc.name == "custom short token" {
				// Existing absolute sessions survive a shorter refresh policy.
				config := runtimeConfig(t)
				config.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
				config.SessionTTL, config.RefreshTTL = tc.sessionTTL, tc.refreshTTL
				var err error
				runtime, err = postgres.NewRuntime(postgres.Config{
					DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
				})
				require.NoError(t, err)
				short, err := runtime.Refresh(t.Context(), original)
				require.NoError(t, err)
				original = short.RefreshToken
			}
			rotated, err := runtime.Refresh(t.Context(), original)
			require.NoError(t, err)
			if tc.name == "custom short token" {
				// Keep the chain live while its earliest token expires.
				for range 3 {
					clock.Add(int64(90 * time.Minute))
					rotated, err = runtime.Refresh(t.Context(), rotated.RefreshToken)
					require.NoError(t, err)
				}
			} else {
				clock.Add(int64(tc.advance))
			}
			cleaned := retentionCleanup(t, runtime, clock, tc.retention)
			require.Zero(t, cleaned.RefreshTokens, "live family history must survive token consumption and expiry")
			require.Zero(t, cleaned.RefreshFamilies)
			require.Zero(t, cleaned.Sessions)
			// A forged secret for a retained selector must not trigger revocation.
			parts := strings.Split(original, ".")
			if parts[2][0] == 'A' {
				parts[2] = "B" + parts[2][1:]
			} else {
				parts[2] = "A" + parts[2][1:]
			}
			_, err = runtime.Refresh(t.Context(), strings.Join(parts, "."))
			require.ErrorIs(t, err, goauth.ErrInvalidToken)
			current, err := runtime.Refresh(t.Context(), rotated.RefreshToken)
			require.NoError(t, err)
			_, err = runtime.Refresh(t.Context(), original)
			require.ErrorIs(t, err, goauth.ErrRefreshReplay)
			_, err = runtime.AuthenticateSession(t.Context(), current.AccessToken)
			require.ErrorIs(t, err, goauth.ErrSessionRevoked)
			_, err = runtime.Refresh(t.Context(), current.RefreshToken)
			require.ErrorIs(t, err, goauth.ErrSessionRevoked)
			var revoked, replayed bool
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT revoked_at IS NOT NULL, replayed_at IS NOT NULL
FROM auth_refresh_families WHERE session_id=$1`, current.Session.ID).Scan(&revoked, &replayed))
			require.True(t, revoked)
			require.True(t, replayed)
			var audits int
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_security_audit_events
WHERE subject_id=$1 AND event_type='refresh.replay'`, registered.Account.Subject.ID).Scan(&audits))
			require.Equal(t, 1, audits)
		})
	}
}

func TestPostgresCleanupRemovesEndedRefreshFamiliesAfterRetention(t *testing.T) {
	for _, end := range []string{"session expiry", "session revocation", "family revocation"} {
		t.Run(end, func(t *testing.T) {
			runtime, db, clock := refreshRetentionRuntime(t, 48*time.Hour, 48*time.Hour)
			registered := register(t, runtime, "ended.retention@example.test")
			_, err := runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
			require.NoError(t, err)
			endedAt := time.Unix(0, clock.Load()).UTC().Add(time.Hour)
			switch end {
			case "session expiry":
				endedAt = registered.Tokens.Session.ExpiresAt
			case "session revocation":
				_, err = db.ExecContext(t.Context(), `UPDATE auth_sessions SET revoked_at=$1 WHERE id=$2`, endedAt, registered.Tokens.Session.ID)
			case "family revocation":
				_, err = db.ExecContext(t.Context(), `UPDATE auth_refresh_families SET revoked_at=$1 WHERE session_id=$2`, endedAt, registered.Tokens.Session.ID)
			}
			require.NoError(t, err)
			clock.Store(endedAt.Add(24 * time.Hour).UnixNano())
			cleaned := retentionCleanup(t, runtime, clock, 0)
			require.Zero(t, cleaned.RefreshTokens, "keep the existing strict retention boundary")
			clock.Add(int64(time.Microsecond))
			cleaned = retentionCleanup(t, runtime, clock, 0)
			require.EqualValues(t, 2, cleaned.RefreshTokens, "remove the whole self-referencing chain")
			require.EqualValues(t, 1, cleaned.RefreshFamilies)
			if end == "family revocation" {
				require.Zero(t, cleaned.Sessions)
			} else {
				require.EqualValues(t, 1, cleaned.Sessions)
			}
			cleaned = retentionCleanup(t, runtime, clock, 0)
			require.Zero(t, cleaned.RefreshTokens)
			require.Zero(t, cleaned.RefreshFamilies)
		})
	}
}

func TestPostgresCleanupSerializesWithRefresh(t *testing.T) {
	for _, order := range []string{"refresh first", "cleanup first"} {
		t.Run(order, func(t *testing.T) {
			runtime, db, clock := refreshRetentionRuntime(t, 0, 0)
			registered := register(t, runtime, "concurrent.retention@example.test")
			live, err := runtime.Login(t.Context(), login("concurrent.retention@example.test", sessionPreparationPassword))
			require.NoError(t, err)
			old := time.Unix(0, clock.Load()).UTC().Add(-25 * time.Hour)
			_, err = db.ExecContext(t.Context(), `UPDATE auth_sessions SET expires_at=$1 WHERE id=$2`, old, registered.Tokens.Session.ID)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			refreshed := make(chan error, 1)
			if order == "refresh first" {
				locked, release := make(chan struct{}), make(chan struct{})
				go func() {
					refreshed <- runtime.InAuthTransaction(ctx, func(ctx context.Context) error {
						_, refreshErr := runtime.Refresh(ctx, live.Tokens.RefreshToken)
						close(locked)
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
						return refreshErr
					})
				}()
				<-locked
				cleaned := retentionCleanup(t, runtime, clock, 0)
				close(release)
				require.NoError(t, <-refreshed)
				require.Zero(t, cleaned.Sessions, "skip a subject owned by a security writer")
			} else {
				blocker, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = blocker.Rollback() }()
				_, err = blocker.ExecContext(ctx, `LOCK auth_refresh_tokens IN SHARE MODE`)
				require.NoError(t, err)
				cleaned := make(chan error, 1)
				go func() {
					_, cleanupErr := runtime.Cleanup(ctx, postgres.CleanupPolicy{Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() }})
					cleaned <- cleanupErr
				}()
				waitRetentionQuery(t, db, "DELETE FROM auth_refresh_tokens%")
				go func() { _, refreshErr := runtime.Refresh(ctx, live.Tokens.RefreshToken); refreshed <- refreshErr }()
				waitRetentionQuery(t, db, "SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE%")
				require.NoError(t, blocker.Commit())
				require.NoError(t, <-cleaned)
				require.NoError(t, <-refreshed)
			}
			retentionCleanup(t, runtime, clock, 0)
			var oldSessions int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM auth_sessions WHERE id=$1`, registered.Tokens.Session.ID).Scan(&oldSessions))
			require.Zero(t, oldSessions)
		})
	}
}

func waitRetentionQuery(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
WHERE datname=current_database() AND wait_event_type='Lock' AND ltrim(query) LIKE $1)`, query).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, time.Millisecond)
}
