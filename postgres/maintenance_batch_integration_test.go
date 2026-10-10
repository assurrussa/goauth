//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/postgres"
)

func assertCleanupBatchBounds(t *testing.T, result postgres.CleanupBatchResult, limit int) {
	t.Helper()
	values := []int64{
		result.PasswordResets, result.EmailChallenges, result.EmailChanges,
		result.RefreshTokens, result.Sessions, result.OIDCRequests, result.OIDCCodes,
		result.OIDCRefreshTokens, result.RateEvents, result.AuditEvents,
		result.NotificationsExpired, result.NotificationReceipts,
	}
	var total int64
	for _, value := range values {
		require.GreaterOrEqual(t, value, int64(0))
		require.LessOrEqual(t, value, int64(limit))
		total += value
	}
	for _, value := range []int64{result.RefreshFamilies, result.OIDCRefreshFamilies} {
		require.GreaterOrEqual(t, value, int64(0))
		require.LessOrEqual(t, value, int64(min(limit, 32)))
		total += value
	}
	require.LessOrEqual(t, total, int64(12*limit+2*min(limit, 32)))
}

func maintenanceCount(t *testing.T, db *sql.DB, query string, args ...any) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.QueryRowContext(t.Context(), query, args...).Scan(&count))
	return count
}

func maintenanceExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), query, args...)
	require.NoError(t, err)
}

func TestCleanupBatchCanonicalBoundsCountEveryDeletedRow(t *testing.T) {
	runtime, db, clock := refreshRetentionRuntime(t, 48*time.Hour, 48*time.Hour)
	registered := register(t, runtime, "bounded-canonical@example.test")
	now := time.Unix(0, clock.Load()).UTC()
	policy := postgres.CleanupPolicy{Now: func() time.Time { return now }}
	// One subject owns five expired sessions; the first owns five families,
	// including a chain larger than a batch. Four sessions have no children.
	maintenanceExec(t, db, `INSERT INTO auth_sessions
(id,subject_id,realm,scope,security_version,created_at,expires_at)
SELECT md5('batch-session-'||g)::uuid,$1,'user','authenticated',1,$2::timestamptz-interval '4 days',
$2::timestamptz-interval '25 hours'
FROM generate_series(1,5) g`, registered.Account.Subject.ID.String(), now)
	maintenanceExec(t, db, `INSERT INTO auth_refresh_families
(id,session_id,subject_id,realm,security_version,created_at)
SELECT md5('batch-family-'||g)::uuid,md5('batch-session-1')::uuid,$1,'user',1,$2::timestamptz-interval '4 days'
FROM generate_series(1,5) g`, registered.Account.Subject.ID.String(), now)
	maintenanceExec(t, db, `INSERT INTO auth_refresh_tokens
(selector,family_id,key_id,secret_digest,created_at,expires_at,consumed_at,replaced_by_selector)
SELECT 'batch-'||f||'-'||n,md5('batch-family-'||f)::uuid,'fixture',decode(repeat('00',32),'hex'),
$1::timestamptz-interval '4 days'+n*interval '1 second',$1::timestamptz-interval '25 hours',
CASE WHEN n<7 THEN $1::timestamptz-interval '3 days' END,
CASE WHEN n<7 THEN 'batch-'||f||'-'||(n+1) END
FROM generate_series(1,5) f CROSS JOIN generate_series(1,7) n`, now)
	countTokens := func() int64 { return maintenanceCount(t, db, `SELECT count(*) FROM auth_refresh_tokens`) }
	countFamilies := func() int64 { return maintenanceCount(t, db, `SELECT count(*) FROM auth_refresh_families`) }
	countSessions := func() int64 { return maintenanceCount(t, db, `SELECT count(*) FROM auth_sessions`) }
	var tokens, families, sessions int64
	for pass := 0; pass < 40 && (tokens != 35 || families != 5 || sessions != 5); pass++ {
		beforeTokens, beforeFamilies, beforeSessions := countTokens(), countFamilies(), countSessions()
		result, err := runtime.CleanupBatch(t.Context(), policy, 2)
		require.NoError(t, err)
		assertCleanupBatchBounds(t, result, 2)
		// Physical table deltas catch hidden FK cascades omitted from counters.
		require.Equal(t, result.RefreshTokens, beforeTokens-countTokens())
		require.Equal(t, result.RefreshFamilies, beforeFamilies-countFamilies())
		require.Equal(t, result.Sessions, beforeSessions-countSessions())
		tokens += result.RefreshTokens
		families += result.RefreshFamilies
		sessions += result.Sessions
	}
	require.EqualValues(t, 35, tokens)
	require.EqualValues(t, 5, families)
	require.EqualValues(t, 5, sessions)
	require.EqualValues(t, 1, countTokens(), "live registration history survives")
	require.EqualValues(t, 1, countFamilies())
	require.EqualValues(t, 1, countSessions())
	_, err := runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
	require.NoError(t, err)
}

func TestCleanupBatchKeepsReplayEvidenceAndStrictCanonicalBoundary(t *testing.T) {
	for _, end := range []string{"session expiry", "session revocation", "family revocation"} {
		t.Run(end, func(t *testing.T) {
			runtime, db, clock := refreshRetentionRuntime(t, 48*time.Hour, 48*time.Hour)
			registered := register(t, runtime, "bounded-replay@example.test")
			original := registered.Tokens.RefreshToken
			rotated, err := runtime.Refresh(t.Context(), original)
			require.NoError(t, err)
			start := time.Unix(0, clock.Load()).UTC()
			now := start.Add(25 * time.Hour)
			clock.Store(now.UnixNano())
			// Expired individual token history still belongs to a live session.
			maintenanceExec(t, db, `UPDATE auth_refresh_tokens SET expires_at=$1
WHERE consumed_at IS NOT NULL`, start.Add(-time.Hour))
			result, err := runtime.CleanupBatch(t.Context(), postgres.CleanupPolicy{Now: func() time.Time { return now }}, 1)
			require.NoError(t, err)
			require.Zero(t, result.RefreshTokens)
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
			if end == "family revocation" {
				_, err = runtime.Refresh(t.Context(), original)
				require.ErrorIs(t, err, goauth.ErrRefreshReplay)
				_, err = runtime.AuthenticateSession(t.Context(), current.AccessToken)
				require.ErrorIs(t, err, goauth.ErrSessionRevoked)
				require.EqualValues(t, 1, maintenanceCount(t, db, `SELECT count(*) FROM auth_security_audit_events
WHERE subject_id=$1 AND event_type='refresh.replay'`, registered.Account.Subject.ID.String()))
			} else if end == "session expiry" {
				maintenanceExec(t, db, `UPDATE auth_sessions SET expires_at=$1 WHERE id=$2`, now, current.Session.ID)
			} else {
				maintenanceExec(t, db, `UPDATE auth_sessions SET revoked_at=$1 WHERE id=$2`, now, current.Session.ID)
			}
			now = now.Add(24 * time.Hour)
			policy := postgres.CleanupPolicy{Now: func() time.Time { return now }}
			result, err = runtime.CleanupBatch(t.Context(), policy, 1)
			require.NoError(t, err)
			require.Zero(t, result.RefreshTokens, "exact strict retention boundary survives")
			now = now.Add(time.Microsecond)
			for range 3 {
				result, err = runtime.CleanupBatch(t.Context(), policy, 1)
				require.NoError(t, err)
				assertCleanupBatchBounds(t, result, 1)
				require.EqualValues(t, 1, result.RefreshTokens)
			}
			require.Zero(t, maintenanceCount(t, db, `SELECT count(*) FROM auth_refresh_tokens`))
		})
	}
}

func TestCleanupBatchSkipsBusyCanonicalSubjectAndContinues(t *testing.T) {
	runtime, db, clock := refreshRetentionRuntime(t, 48*time.Hour, 48*time.Hour)
	registered := register(t, runtime, "bounded-lock@example.test")
	now := time.Unix(0, clock.Load()).UTC()
	maintenanceExec(t, db, `UPDATE auth_sessions SET expires_at=$1 WHERE id=$2`,
		now.Add(-25*time.Hour), registered.Tokens.Session.ID)
	blocker, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Rollback() })
	_, err = blocker.ExecContext(t.Context(), `SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`,
		registered.Account.Subject.ID.String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	policy := postgres.CleanupPolicy{Now: func() time.Time { return now }}
	result, err := runtime.CleanupBatch(ctx, policy, 1)
	require.NoError(t, err)
	require.Zero(t, result.RefreshTokens)
	require.Zero(t, result.Sessions)
	require.NoError(t, blocker.Commit())
	result, err = runtime.CleanupBatch(ctx, policy, 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.RefreshTokens)
	require.EqualValues(t, 1, result.RefreshFamilies)
	require.EqualValues(t, 1, result.Sessions)
}

func TestCleanupBatchFamilyEndDoesNotDeleteLiveSession(t *testing.T) {
	runtime, db, clock := refreshRetentionRuntime(t, 7*24*time.Hour, 7*24*time.Hour)
	registered := register(t, runtime, "bounded-family-end@example.test")
	now := time.Unix(0, clock.Load()).UTC()
	maintenanceExec(t, db, `UPDATE auth_refresh_families SET revoked_at=$1 WHERE session_id=$2`,
		now.Add(-25*time.Hour), registered.Tokens.Session.ID)
	result, err := runtime.CleanupBatch(t.Context(), postgres.CleanupPolicy{Now: func() time.Time { return now }}, 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.RefreshTokens)
	require.EqualValues(t, 1, result.RefreshFamilies)
	require.Zero(t, result.Sessions)
	require.EqualValues(t, 1, maintenanceCount(t, db,
		`SELECT count(*) FROM auth_sessions WHERE id=$1`, registered.Tokens.Session.ID))
}

func TestCleanupBatchCanonicalMergeAndCycleRemainFKSafe(t *testing.T) {
	runtime, db, clock := refreshRetentionRuntime(t, 48*time.Hour, 48*time.Hour)
	registered := register(t, runtime, "bounded-fk@example.test")
	now := time.Unix(0, clock.Load()).UTC()
	maintenanceExec(t, db, `INSERT INTO auth_sessions
(id,subject_id,realm,scope,security_version,created_at,expires_at)
SELECT md5('batch-fk-session')::uuid,$1,'user','authenticated',1,$2::timestamptz-interval '4 days',
$2::timestamptz-interval '25 hours'`,
		registered.Account.Subject.ID.String(), now)
	maintenanceExec(t, db, `INSERT INTO auth_refresh_families
(id,session_id,subject_id,realm,security_version,created_at)
SELECT md5('batch-fk-'||kind)::uuid,md5('batch-fk-session')::uuid,$1,'user',1,$2::timestamptz-interval '4 days'
FROM (VALUES ('merge'),('cycle')) fixture(kind)`, registered.Account.Subject.ID.String(), now)
	maintenanceExec(t, db, `INSERT INTO auth_refresh_tokens
(selector,family_id,key_id,secret_digest,created_at,expires_at,replaced_by_selector)
SELECT selector,md5('batch-fk-'||family)::uuid,'fixture',decode(repeat('00',32),'hex'),
$1::timestamptz-interval '4 days',$1::timestamptz-interval '25 hours',successor
FROM (VALUES ('batch-a','merge','batch-c'),('batch-b','merge','batch-c'),('batch-c','merge',NULL),
('batch-x','cycle','batch-y'),('batch-y','cycle','batch-x')) fixture(selector,family,successor)`, now)
	policy := postgres.CleanupPolicy{Now: func() time.Time { return now }}
	var tokens, families int64
	for range 3 {
		result, err := runtime.CleanupBatch(t.Context(), policy, 2)
		require.NoError(t, err, "merge prefixes must never delete a still-referenced successor")
		assertCleanupBatchBounds(t, result, 2)
		tokens += result.RefreshTokens
		families += result.RefreshFamilies
		require.Zero(t, result.Sessions, "a cycle-bearing family keeps its parent session")
	}
	require.EqualValues(t, 3, tokens)
	require.EqualValues(t, 1, families)
	require.EqualValues(t, 2, maintenanceCount(t, db,
		`SELECT count(*) FROM auth_refresh_tokens WHERE selector IN ('batch-x','batch-y')`))
}

func TestCleanupBatchOIDCUsesRequestedBoundsAndContinuation(t *testing.T) {
	runtime, state, refresh := sessionOIDCFixture(t)
	base := refresh.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return base })
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		for range 5 {
			if err := state.SaveRequest(ctx, sessionOIDCRequest(base)); err != nil {
				return err
			}
			if err := state.SaveCode(ctx, sessionOIDCCode(refresh)); err != nil {
				return err
			}
		}
		if err := state.SaveRefresh(ctx, refresh); err != nil {
			return err
		}
		current := refresh
		for i := range 6 {
			next := current
			next.Token = fmt.Sprintf("cleanup-batch-%d-%s", i, refresh.FamilyID)
			if err := state.RotateRefresh(ctx, current, next, base); err != nil {
				return err
			}
			current = next
		}
		return nil
	}))
	now := base.Add(10 * 24 * time.Hour)
	policy := postgres.CleanupPolicy{Now: func() time.Time { return now }}
	var requests, codes, tokens, families int64
	for range 4 {
		beforeTokens := maintenanceCount(t, runtime.Database(), `SELECT count(*) FROM auth_oidc_refresh_tokens`)
		result, err := runtime.CleanupBatch(t.Context(), policy, 2)
		require.NoError(t, err)
		assertCleanupBatchBounds(t, result, 2)
		require.Equal(t, result.OIDCRefreshTokens, beforeTokens-maintenanceCount(t, runtime.Database(),
			`SELECT count(*) FROM auth_oidc_refresh_tokens`))
		requests += result.OIDCRequests
		codes += result.OIDCCodes
		tokens += result.OIDCRefreshTokens
		families += result.OIDCRefreshFamilies
	}
	require.EqualValues(t, 5, requests)
	require.EqualValues(t, 5, codes)
	require.EqualValues(t, 7, tokens)
	require.EqualValues(t, 1, families)
}
