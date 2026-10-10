//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

// Exercise the new coordinator itself, rather than relying only on Cleanup's
// existing lock-order regression. Observe real SQL lock waits, not a sleep.
func TestCleanupBatchReleasesCanonicalLocksForConcurrentRefresh(t *testing.T) {
	runtime, db, clock := refreshRetentionRuntime(t, 0, 0)
	registered := register(t, runtime, "batch-concurrent@example.test")
	live, err := runtime.Login(t.Context(), login("batch-concurrent@example.test", sessionPreparationPassword))
	require.NoError(t, err)
	now := time.Unix(0, clock.Load()).UTC()
	maintenanceExec(t, db, `UPDATE auth_sessions SET expires_at=$1 WHERE id=$2`,
		now.Add(-25*time.Hour), registered.Tokens.Session.ID)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	blocker, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback() }()
	_, err = blocker.ExecContext(ctx, `LOCK auth_refresh_tokens IN SHARE MODE`)
	require.NoError(t, err)
	cleaned, refreshed := make(chan error, 1), make(chan error, 1)
	go func() {
		_, cleanupErr := runtime.CleanupBatch(ctx, postgres.CleanupPolicy{Now: func() time.Time { return now }}, 1)
		cleaned <- cleanupErr
	}()
	waitRetentionQuery(t, db, "WITH RECURSIVE chain%")
	go func() {
		_, refreshErr := runtime.Refresh(ctx, live.Tokens.RefreshToken)
		refreshed <- refreshErr
	}()
	waitRetentionQuery(t, db, "SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE%")
	require.NoError(t, blocker.Commit())
	require.NoError(t, <-cleaned)
	require.NoError(t, <-refreshed)
	require.Zero(t, maintenanceCount(t, db, `SELECT count(*) FROM auth_sessions WHERE id=$1`, registered.Tokens.Session.ID))
	require.EqualValues(t, 1, maintenanceCount(t, db, `SELECT count(*) FROM auth_sessions WHERE id=$1`, live.Tokens.Session.ID))
}
