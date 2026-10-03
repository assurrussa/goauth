//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func rateCleanupRuntime(t *testing.T, db *sql.DB, now time.Time) *postgres.Runtime {
	t.Helper()
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.Now = func() time.Time { return now }
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	return runtime
}

func seedRateCleanup(t *testing.T, db *sql.DB, at time.Time, count int) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `INSERT INTO auth_rate_limit_events (key_id,bucket_digest,action,occurred_at)
SELECT 'cleanup-fixture',decode(repeat('00',32),'hex'),'cleanup-fixture',$1 FROM generate_series(1,$2::int)`, at, count)
	require.NoError(t, err)
}

func rateCleanupCount(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var count int64
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_rate_limit_events`).Scan(&count))
	return count
}

func TestPostgresRateEventCleanupRetentionAndNoCollateralChanges(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Date(2050, 1, 2, 12, 0, 0, 0, time.UTC)
	runtime := rateCleanupRuntime(t, db, now)
	seedPreRetirementSchema(t, db, 6)
	before := retirementMigrationSnapshot(t, db, 7)
	delete(before, "auth_rate_limit_events")
	cutoff := now.Add(-25 * time.Hour)
	seedRateCleanup(t, db, cutoff.Add(-time.Microsecond), 5)
	seedRateCleanup(t, db, cutoff, 1)
	seedRateCleanup(t, db, now.Add(-24*time.Hour), 1)
	seedRateCleanup(t, db, now, 1)
	count, err := runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{Limit: 2})
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	count, err = runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{Limit: 1000})
	require.NoError(t, err)
	require.EqualValues(t, 6, count) // Three seeded historical rows plus five expired fixture rows total.
	require.EqualValues(t, 3, rateCleanupCount(t, db))
	count, err = runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{
		Before: now.Add(-24 * time.Hour), Limit: 1,
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, count) // The exact default cutoff is older than this explicit cutoff.
	require.EqualValues(t, 2, rateCleanupCount(t, db), "inclusive current 24h window must survive")
	after := retirementMigrationSnapshot(t, db, 7)
	delete(after, "auth_rate_limit_events")
	require.True(t, reflect.DeepEqual(before, after), "rate-only maintenance changed unrelated canonical data")
}

func TestPostgresRateEventCleanupPreservesLongDirectStoreWindow(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Date(2050, 1, 2, 12, 0, 0, 0, time.UTC)
	runtime := rateCleanupRuntime(t, db, now)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	request := goauth.RateLimitRequest{Action: "long-window", Bucket: goauth.SecretDigest{
		KeyID: "fixture", Digest: make([]byte, 32),
	}, Window: 48 * time.Hour, Limit: 1, Now: now.Add(-30 * time.Hour)}
	admitted, err := store.TakeRateLimit(t.Context(), request)
	require.NoError(t, err)
	require.True(t, admitted.Allowed, "direct Store supports windows beyond Runtime's 24h maximum")
	// The caller must use 49h here, not the API's 25h default, to preserve this consumer.
	count, err := runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{
		Before: now.Add(-49 * time.Hour), Limit: 1000,
	})
	require.NoError(t, err)
	require.Zero(t, count)
	request.Now = now
	admitted, err = store.TakeRateLimit(t.Context(), request)
	require.NoError(t, err)
	require.False(t, admitted.Allowed)
}

func TestPostgresRateEventCleanupLockedPrefixIsBounded(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Now().UTC()
	runtime := rateCleanupRuntime(t, db, now)
	seedRateCleanup(t, db, now.Add(-48*time.Hour), 2000)
	locked, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = locked.Rollback() }()
	_, err = locked.ExecContext(t.Context(), `SELECT id FROM auth_rate_limit_events ORDER BY occurred_at,id LIMIT 1000 FOR UPDATE`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for range 2 {
		count, err := runtime.CleanupRateLimitEvents(ctx, postgres.RateLimitCleanupRequest{Limit: 1000})
		require.NoError(t, err)
		require.Zero(t, count, "must not walk past the first locked candidate batch")
	}
	require.EqualValues(t, 2000, rateCleanupCount(t, db))
	require.NoError(t, locked.Rollback())
	count, err := runtime.CleanupRateLimitEvents(ctx, postgres.RateLimitCleanupRequest{Limit: 1000})
	require.NoError(t, err)
	require.EqualValues(t, 1000, count)
	require.EqualValues(t, 1000, rateCleanupCount(t, db))
}

func TestPostgresRateEventCleanupConcurrentCleanersAndAdmission(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Now().UTC()
	runtime := rateCleanupRuntime(t, db, now)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	seedRateCleanup(t, db, now.Add(-48*time.Hour), 1200)
	type outcome struct {
		count int64
		err   error
	}
	results := make(chan outcome, 2)
	admissions := make(chan error, 1)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			count, err := runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{Limit: 1000})
			results <- outcome{count, err}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for range 20 {
			result, err := store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
				Action: "cleanup-concurrent", Bucket: goauth.SecretDigest{KeyID: "fixture", Digest: make([]byte, 32)},
				Window: 24 * time.Hour, Limit: 20, Now: now,
			})
			if err == nil && !result.Allowed {
				err = errors.New("concurrent admission unexpectedly denied")
			}
			if err != nil {
				admissions <- err
				return
			}
		}
		admissions <- nil
	}()
	close(start)
	wg.Wait()
	var deleted int64
	for range 2 {
		result := <-results
		require.NoError(t, result.err)
		require.LessOrEqual(t, result.count, int64(1000))
		deleted += result.count
	}
	require.NoError(t, <-admissions)
	require.LessOrEqual(t, deleted, int64(1200))
	require.Equal(t, int64(1220)-deleted, rateCleanupCount(t, db))
	var current int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM auth_rate_limit_events WHERE occurred_at=$1`, now).Scan(&current))
	require.Equal(t, 20, current)
}

func TestPostgresRateEventCleanupRejectsManagedScopes(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Now().UTC()
	runtime := rateCleanupRuntime(t, db, now)
	foreignDB := integrationDB(t)
	foreign := rateCleanupRuntime(t, foreignDB, now)
	seedRateCleanup(t, db, now.Add(-48*time.Hour), 3)
	for _, owner := range []*postgres.Runtime{runtime, foreign} {
		require.NoError(t, owner.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			count, err := runtime.CleanupRateLimitEvents(ctx, postgres.RateLimitCleanupRequest{Limit: 1000})
			require.Error(t, err)
			require.Zero(t, count)
			return nil
		}))
	}
	require.EqualValues(t, 3, rateCleanupCount(t, db))
}

func TestPostgresRateEventCleanupCancellationRollsBack(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Now().UTC()
	runtime := rateCleanupRuntime(t, db, now)
	seedRateCleanup(t, db, now.Add(-48*time.Hour), 3)
	blocker, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback() }()
	_, err = blocker.ExecContext(t.Context(), `LOCK TABLE auth_rate_limit_events IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		count, err := runtime.CleanupRateLimitEvents(ctx, postgres.RateLimitCleanupRequest{Limit: 3})
		if count != 0 {
			err = errors.New("cancelled cleanup exposed provisional count")
		}
		done <- err
	}()
	require.Eventually(t, func() bool {
		var blocked bool
		err := db.QueryRowContext(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%WITH candidates AS MATERIALIZED%')`).Scan(&blocked)
		return err == nil && blocked
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.NoError(t, blocker.Rollback())
	require.EqualValues(t, 3, rateCleanupCount(t, db))
}

func TestPostgresRateEventCleanupUnknownCommitCountAndRetry(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rolled back", true: "durably committed"}[committed], func(t *testing.T) {
			observer := integrationDB(t)
			resetSchema(t, observer)
			config, err := pgx.ParseConfig(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
			require.NoError(t, err)
			fault := &renameCommitFault{commit: committed}
			db := sql.OpenDB(renameFaultConnector{Connector: stdlib.GetConnector(*config), fault: fault})
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			now := time.Now().UTC()
			runtime := rateCleanupRuntime(t, db, now)
			seedRateCleanup(t, observer, now.Add(-48*time.Hour), 4)
			fault.armed.Store(true)
			count, err := runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{Limit: 2})
			require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
			require.Zero(t, count)
			require.False(t, fault.armed.Load())
			want := int64(4)
			if committed {
				want = 2
			}
			require.Equal(t, want, rateCleanupCount(t, observer))
			count, err = runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{Limit: 2})
			require.NoError(t, err)
			require.EqualValues(t, 2, count, "retry reports this new batch only")
			require.Equal(t, want-2, rateCleanupCount(t, observer))
		})
	}
}

func TestPostgresRateEventCleanupConcurrentTimestampUpdate(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Now().UTC()
	runtime := rateCleanupRuntime(t, db, now)
	seedRateCleanup(t, db, now.Add(-48*time.Hour), 3)
	updater, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = updater.Rollback() }()
	var moved int64
	require.NoError(t, updater.QueryRowContext(t.Context(), `UPDATE auth_rate_limit_events SET occurred_at=$1
WHERE id=(SELECT min(id) FROM auth_rate_limit_events) RETURNING id`, now).Scan(&moved))
	// The cleanup snapshot sees the old eligible tuple; row locking must skip
	// this in-flight update rather than deleting its newer live-window version.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	count, err := runtime.CleanupRateLimitEvents(ctx, postgres.RateLimitCleanupRequest{Limit: 2})
	require.NoError(t, err)
	require.EqualValues(t, 1, count, "locked candidate must not be replaced with a later eligible row")
	require.NoError(t, updater.Commit())
	count, err = runtime.CleanupRateLimitEvents(ctx, postgres.RateLimitCleanupRequest{Limit: 2})
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	var retained time.Time
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT occurred_at FROM auth_rate_limit_events WHERE id=$1`, moved).Scan(&retained))
	require.WithinDuration(t, now, retained, time.Microsecond)
	require.EqualValues(t, 1, rateCleanupCount(t, db))
}

func TestPostgresRateEventCleanupCommitRejectionRollsBackBatch(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Now().UTC()
	runtime := rateCleanupRuntime(t, db, now)
	seedRateCleanup(t, db, now.Add(-48*time.Hour), 3)
	_, err := db.ExecContext(t.Context(), `CREATE FUNCTION rate_cleanup_reject_commit() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic cleanup commit rejection'; END $$;
CREATE CONSTRAINT TRIGGER rate_cleanup_reject_commit AFTER DELETE ON auth_rate_limit_events
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rate_cleanup_reject_commit()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `DROP TRIGGER rate_cleanup_reject_commit ON auth_rate_limit_events;
DROP FUNCTION rate_cleanup_reject_commit()`)
		require.NoError(t, err)
	})
	count, err := runtime.CleanupRateLimitEvents(t.Context(), postgres.RateLimitCleanupRequest{Limit: 3})
	require.Error(t, err)
	require.NotErrorIs(t, err, goauth.ErrOperationOutcomeUnknown, "PostgreSQL explicitly rejected commit")
	require.Zero(t, count, "provisional deletions are never successful output")
	require.EqualValues(t, 3, rateCleanupCount(t, db), "commit rejection rolls back the complete batch")
}
