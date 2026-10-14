//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

type notificationLifecycleFixture struct {
	db      *sql.DB
	runtime *postgres.Runtime
	subject goauth.SubjectID
	now     time.Time
}

func newNotificationLifecycleFixture(t *testing.T) notificationLifecycleFixture {
	t.Helper()
	db := integrationDB(t)
	resetSchema(t, db)
	now := time.Date(2050, 1, 2, 12, 0, 0, 0, time.UTC)
	config := runtimeConfig(t)
	config.EventSink = nil
	config.Now = func() time.Time { return now }
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, AutoMigrate: true, ConnectionTimeout: 30 * time.Second,
		Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Close()) })
	subject := goauth.NewSubjectID()
	_, err = db.ExecContext(t.Context(), `
INSERT INTO auth_subjects(id,status,security_version,created_at,updated_at)
VALUES($1,'active',1,$2,$2)`, subject, now)
	require.NoError(t, err)
	return notificationLifecycleFixture{db: db, runtime: runtime, subject: subject, now: now}
}

func (f notificationLifecycleFixture) insert(
	t *testing.T, state string, deadline time.Time, attempts int, scrubbed bool,
) string {
	t.Helper()
	id := goauth.NewSubjectID().String()
	var payload any = []byte{1, 2, 3}
	nonce, additional := []byte{4}, []byte{5}
	if scrubbed {
		payload, nonce, additional = nil, []byte{}, []byte{}
	}
	var token, leasedUntil, deliveredAt any
	if state == "leased" {
		token, leasedUntil = goauth.NewSubjectID().String(), f.now.Add(time.Minute)
	}
	if state == "delivered" {
		deliveredAt = deadline
	}
	_, err := f.db.ExecContext(t.Context(), `
INSERT INTO auth_notification_deliveries
(id,subject_id,event_type,reference_id,valid_until,key_id,nonce,ciphertext,additional_data,
 created_at,delete_after,state,attempts,next_attempt_at,lease_token,leased_until,delivered_at,last_failure)
VALUES($1,$2,'fixture','reference',$3,'fixture-key',$4,$5,$6,$7,$3,$8,$9,$7,$10,$11,$12,'sender')`,
		id, f.subject, deadline, nonce, payload, additional, f.now.Add(-30*24*time.Hour),
		state, attempts, token, leasedUntil, deliveredAt)
	require.NoError(t, err)
	return id
}

func notificationLifecycleSnapshot(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var snapshot string
	require.NoError(t, db.QueryRowContext(t.Context(),
		"SELECT to_jsonb(n)::text FROM auth_notification_deliveries n WHERE id=$1", id).Scan(&snapshot))
	return snapshot
}

func TestCancelNotificationScrubsWithoutChangingBudgetOrDeadlines(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	for _, state := range []string{"pending", "blocked"} {
		id := f.insert(t, state, f.now.Add(time.Hour), 2, false)
		var before, after string
		const preserved = `SELECT (to_jsonb(n)-'state'-'last_failure'-'ciphertext'-'nonce'-'additional_data'-'lease_token'-'leased_until')::text
FROM auth_notification_deliveries n WHERE id=$1`
		require.NoError(t, f.db.QueryRowContext(t.Context(), preserved, id).Scan(&before))
		changed, err := f.runtime.CancelNotification(t.Context(), id)
		require.NoError(t, err)
		require.True(t, changed)
		var scrubbed bool
		require.NoError(t, f.db.QueryRowContext(t.Context(), `
SELECT state='cancelled' AND last_failure='operator_cancelled' AND ciphertext IS NULL AND octet_length(nonce)=0
 AND octet_length(additional_data)=0 AND lease_token IS NULL AND leased_until IS NULL
 AND delivered_at IS NULL FROM auth_notification_deliveries WHERE id=$1`, id).Scan(&scrubbed))
		require.True(t, scrubbed)
		require.NoError(t, f.db.QueryRowContext(t.Context(), preserved, id).Scan(&after))
		require.Equal(t, before, after)
		before = notificationLifecycleSnapshot(t, f.db, id)
		changed, err = f.runtime.CancelNotification(t.Context(), id)
		require.NoError(t, err)
		require.False(t, changed)
		require.Equal(t, before, notificationLifecycleSnapshot(t, f.db, id))
	}
	stats, err := f.runtime.NotificationStats(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 2, stats.Cancelled)
	require.Nil(t, stats.OldestQueuedAt)
}

func TestCancelNotificationIneligibleRowsAreUnchanged(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	for _, state := range []string{"leased", "delivered", "exhausted", "expired", "cancelled"} {
		id := f.insert(t, state, f.now.Add(time.Hour), 1, state != "leased")
		before := notificationLifecycleSnapshot(t, f.db, id)
		changed, err := f.runtime.CancelNotification(t.Context(), id)
		require.NoError(t, err)
		require.False(t, changed, state)
		require.Equal(t, before, notificationLifecycleSnapshot(t, f.db, id))
	}
	for name, row := range map[string]struct {
		state    string
		deadline time.Time
		attempts int
		scrubbed bool
		extraSQL string
	}{
		"expired deadline": {"pending", f.now.Add(-time.Second), 0, false, ""},
		"exact deadline":   {"blocked", f.now, 0, false, ""},
		"spent budget":     {"pending", f.now.Add(time.Hour), 10, false, ""},
		"missing payload":  {"pending", f.now.Add(time.Hour), 0, true, ""},
		"elapsed lease":    {"leased", f.now.Add(time.Hour), 1, false, "UPDATE auth_notification_deliveries SET leased_until=$2 WHERE id=$1"},
		"stray lease":      {"pending", f.now.Add(time.Hour), 0, false, "UPDATE auth_notification_deliveries SET leased_until=$2 WHERE id=$1"},
	} {
		id := f.insert(t, row.state, row.deadline, row.attempts, row.scrubbed)
		if row.extraSQL != "" {
			_, err := f.db.ExecContext(t.Context(), row.extraSQL, id, f.now.Add(-time.Second))
			require.NoError(t, err)
		}
		before := notificationLifecycleSnapshot(t, f.db, id)
		changed, err := f.runtime.CancelNotification(t.Context(), id)
		require.NoError(t, err)
		require.False(t, changed, name)
		require.Equal(t, before, notificationLifecycleSnapshot(t, f.db, id))
	}
	changed, err := f.runtime.CancelNotification(t.Context(), goauth.NewSubjectID().String())
	require.NoError(t, err)
	require.False(t, changed)
}

func TestCancelNotificationAndHostAuditRollbackTogether(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	_, err := f.db.ExecContext(t.Context(), "CREATE TABLE goauth_lifecycle_host_audit(id UUID PRIMARY KEY)")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, dropErr := f.db.ExecContext(context.Background(), "DROP TABLE goauth_lifecycle_host_audit")
		require.NoError(t, dropErr)
	})
	id := f.insert(t, "pending", f.now.Add(time.Hour), 1, false)
	before := notificationLifecycleSnapshot(t, f.db, id)
	rollback := errors.New("host audit rejected")
	write := func(ctx context.Context) error {
		changed, cancelErr := f.runtime.CancelNotification(ctx, id)
		if cancelErr != nil || !changed {
			return errors.New("cancellation did not join host transaction")
		}
		exec, execErr := f.runtime.SQLExecutor(ctx)
		if execErr != nil {
			return execErr
		}
		_, execErr = exec.ExecContext(ctx, "INSERT INTO goauth_lifecycle_host_audit VALUES($1)", id)
		return execErr
	}
	err = f.runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		if writeErr := write(ctx); writeErr != nil {
			return writeErr
		}
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	require.Equal(t, before, notificationLifecycleSnapshot(t, f.db, id))
	var auditCount int
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM goauth_lifecycle_host_audit").Scan(&auditCount))
	require.Zero(t, auditCount)
	require.NoError(t, f.runtime.InAuthTransaction(t.Context(), write))
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM goauth_lifecycle_host_audit").Scan(&auditCount))
	require.Equal(t, 1, auditCount)
}

func TestCancelNotificationWorkerFencesAndFutureOnlySemantics(t *testing.T) {
	t.Run("cancel before claim", func(t *testing.T) {
		db := integrationDB(t)
		var sends atomic.Int32
		runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
			func(context.Context, goauth.NotificationDelivery) error { sends.Add(1); return nil },
		))
		account := register(t, runtime, "cancel.before.claim@example.test")
		require.NoError(t, runtime.SendEmailChallenge(t.Context(), account.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification))
		id := managedNotificationID(t, db, account.Account.Subject.ID)
		changed, err := runtime.CancelNotification(t.Context(), id)
		require.NoError(t, err)
		require.True(t, changed)
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		defer cancel()
		require.NoError(t, runtime.RunNotifications(ctx))
		require.Zero(t, sends.Load())
		waitManagedNotificationState(t, db, id, "cancelled")
	})

	t.Run("leased send cannot be cancelled", func(t *testing.T) {
		db := integrationDB(t)
		started, release := make(chan struct{}), make(chan struct{})
		notifyStarted := sync.OnceFunc(func() { close(started) })
		releaseSend := sync.OnceFunc(func() { close(release) })
		defer releaseSend()
		runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
			func(ctx context.Context, _ goauth.NotificationDelivery) error {
				notifyStarted()
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		))
		account := register(t, runtime, "cancel.leased@example.test")
		require.NoError(t, runtime.SendEmailChallenge(t.Context(), account.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification))
		id := managedNotificationID(t, db, account.Account.Subject.ID)
		startManagedNotificationWorker(t, runtime)
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not enter sender")
		}
		before := notificationLifecycleSnapshot(t, db, id)
		changed, err := runtime.CancelNotification(t.Context(), id)
		require.NoError(t, err)
		require.False(t, changed)
		require.Equal(t, before, notificationLifecycleSnapshot(t, db, id))
		releaseSend()
		waitManagedNotificationState(t, db, id, "delivered")
	})
}

func TestNotificationReceiptCleanupBoundsSkipsLocksAndPreservesFences(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	cutoff := f.now.Add(-7 * 24 * time.Hour)
	old := cutoff.Add(-time.Second)
	lockedID := f.insert(t, "cancelled", old, 1, true)
	for _, state := range []string{"delivered", "exhausted", "expired", "cancelled"} {
		f.insert(t, state, old, 1, true)
	}
	keep := []string{
		f.insert(t, "pending", old, 0, false),
		f.insert(t, "pending", old, 0, true),
		f.insert(t, "blocked", old, 0, true),
		f.insert(t, "leased", old, 1, true),
		f.insert(t, "cancelled", cutoff, 1, true),
		f.insert(t, "expired", old, 1, false),
		f.insert(t, "delivered", f.now.Add(time.Hour), 1, true),
	}
	_, err := f.db.ExecContext(t.Context(),
		"UPDATE auth_notification_deliveries SET delivered_at=$2 WHERE id=$1", keep[len(keep)-1], old)
	require.NoError(t, err)
	recentAcceptance := f.insert(t, "delivered", old, 1, true)
	_, err = f.db.ExecContext(t.Context(),
		"UPDATE auth_notification_deliveries SET delivered_at=$2 WHERE id=$1", recentAcceptance, cutoff)
	require.NoError(t, err)
	keep = append(keep, recentAcceptance)
	dirtyNonce := f.insert(t, "expired", old, 1, true)
	_, err = f.db.ExecContext(t.Context(),
		"UPDATE auth_notification_deliveries SET nonce=decode('01','hex') WHERE id=$1", dirtyNonce)
	require.NoError(t, err)
	keep = append(keep, dirtyNonce)
	snapshots := make(map[string]string, len(keep))
	for _, id := range keep {
		snapshots[id] = notificationLifecycleSnapshot(t, f.db, id)
	}
	locked, err := f.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = locked.Rollback() }()
	_, err = locked.ExecContext(t.Context(), "SELECT id FROM auth_notification_deliveries WHERE id=$1 FOR UPDATE", lockedID)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	count, err := f.runtime.CleanupNotificationReceipts(ctx, 0, 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	count, err = f.runtime.CleanupNotificationReceipts(ctx, 0, 1000)
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	count, err = f.runtime.CleanupNotificationReceipts(ctx, 0, 1000)
	require.NoError(t, err)
	require.Zero(t, count, "locked receipt must wait for a later pass")
	require.NoError(t, locked.Rollback())
	count, err = f.runtime.CleanupNotificationReceipts(ctx, 0, 1000)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	for _, id := range keep {
		require.Equal(t, snapshots[id], notificationLifecycleSnapshot(t, f.db, id))
	}
	var subjects int
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_subjects WHERE id=$1", f.subject).Scan(&subjects))
	require.Equal(t, 1, subjects)
}

func TestNotificationReceiptCleanupRollsBackInManagedScope(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	id := f.insert(t, "cancelled", f.now.Add(-8*24*time.Hour), 2, true)
	before := notificationLifecycleSnapshot(t, f.db, id)
	rollback := errors.New("rollback receipt cleanup")
	err := f.runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		count, cleanupErr := f.runtime.CleanupNotificationReceipts(ctx, 0, 1)
		if cleanupErr != nil {
			return cleanupErr
		}
		if count != 1 {
			return errors.New("cleanup did not join transaction")
		}
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	require.Equal(t, before, notificationLifecycleSnapshot(t, f.db, id))
}
