//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestManagedNotificationRejectedIsNotDeliveredOrRetried(t *testing.T) {
	db := integrationDB(t)
	var calls atomic.Int32
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error {
			calls.Add(1)
			return errors.Join(goauth.ErrNotificationRejected, errors.New("private-provider-token"))
		},
	))
	registered := register(t, runtime, "terminal-notification@example.test")
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)
	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, id, "exhausted")
	var failure string
	var scrubbed, undelivered bool
	var attempts int
	require.NoError(t, db.QueryRow(`SELECT last_failure,attempts,
 ciphertext IS NULL AND octet_length(nonce)=0 AND octet_length(additional_data)=0,
 delivered_at IS NULL FROM auth_notification_deliveries WHERE id=$1`, id).
		Scan(&failure, &attempts, &scrubbed, &undelivered))
	require.Equal(t, "sender_rejected", failure)
	require.Equal(t, 1, attempts)
	require.True(t, scrubbed)
	require.True(t, undelivered)
	time.Sleep(150 * time.Millisecond)
	require.EqualValues(t, 1, calls.Load())
	stats, err := runtime.NotificationStats(t.Context())
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.Exhausted)
	require.Zero(t, stats.Delivered)
}

func TestNotificationBatchExpiryIsBoundedAndTransactionAware(t *testing.T) {
	db := integrationDB(t)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return errors.New("must not send") },
	))
	registered := register(t, runtime, "batch-expiry@example.test")
	for range 3 {
		require.NoError(t, runtime.RequestPasswordReset(t.Context(), registered.Account.PrimaryEmail.DisplayValue))
	}
	_, err := db.Exec(`UPDATE auth_notification_deliveries SET valid_until=now()-interval '1 second'`)
	require.NoError(t, err)
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	count := func(query string) int {
		var n int
		require.NoError(t, db.QueryRow(query).Scan(&n))
		return n
	}
	before := count(`SELECT count(*) FROM auth_notification_deliveries WHERE ciphertext IS NOT NULL`)
	require.Equal(t, 4, before)
	resets := count(`SELECT count(*) FROM auth_password_reset_records`)
	audits := count(`SELECT count(*) FROM auth_security_audit_events`)
	rollback := errors.New("rollback expiry")
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		n, expireErr := runtime.ExpireNotifications(ctx, 2)
		require.NoError(t, expireErr)
		require.EqualValues(t, 2, n)
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	require.Equal(t, before, count(`SELECT count(*) FROM auth_notification_deliveries WHERE ciphertext IS NOT NULL`))
	for _, limit := range []int{0, -1, 1001} {
		_, err = runtime.ExpireNotifications(t.Context(), limit)
		require.Error(t, err)
	}
	locked, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = locked.Rollback() })
	var lockedID string
	require.NoError(t, locked.QueryRow(`SELECT id FROM auth_notification_deliveries
 WHERE valid_until<=now() ORDER BY created_at,id LIMIT 1 FOR UPDATE`).Scan(&lockedID))
	n, err := runtime.ExpireNotifications(t.Context(), 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
	require.NoError(t, locked.Commit())
	n, err = runtime.ExpireNotifications(t.Context(), 2)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	n, err = runtime.ExpireNotifications(t.Context(), 2)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Equal(t, resets, count(`SELECT count(*) FROM auth_password_reset_records`))
	require.Equal(t, audits, count(`SELECT count(*) FROM auth_security_audit_events`))
	require.Equal(t, 3, count(`SELECT count(*) FROM auth_notification_deliveries
 WHERE state='expired' AND delivered_at IS NULL AND ciphertext IS NULL
 AND octet_length(nonce)=0 AND octet_length(additional_data)=0`))
}

func TestNotificationBatchExpiryFencesLateCompletion(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"rejection", goauth.ErrNotificationRejected}, {"acceptance", nil}, {"unknown", context.DeadlineExceeded}} {
		t.Run(tc.name, func(t *testing.T) { testNotificationBatchExpiryLateCompletion(t, tc.err) })
	}
}

func testNotificationBatchExpiryLateCompletion(t *testing.T, senderErr error) {
	t.Helper()
	db := integrationDB(t)
	entered, release := make(chan struct{}), make(chan struct{})
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(ctx context.Context, _ goauth.NotificationDelivery) error {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			return senderErr
		},
	))
	registered := register(t, runtime, "expiry-rejection@example.test")
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)
	startManagedNotificationWorker(t, runtime)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not start")
	}
	_, err := db.Exec(`UPDATE auth_notification_deliveries SET valid_until=now()-interval '1 second' WHERE id=$1`, id)
	require.NoError(t, err)
	n, err := runtime.ExpireNotifications(t.Context(), 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	close(release)
	time.Sleep(100 * time.Millisecond)
	var state string
	var undelivered bool
	require.NoError(t, db.QueryRow(`SELECT state,delivered_at IS NULL FROM auth_notification_deliveries WHERE id=$1`, id).
		Scan(&state, &undelivered))
	require.Equal(t, "expired", state)
	require.True(t, undelivered)
}
