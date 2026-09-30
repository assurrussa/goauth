//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/testkit"
)

func TestManagedNotificationWritesRollBackTogether(t *testing.T) {
	for _, test := range []struct {
		name    string
		trigger string
	}{
		{
			name: "enqueue failure",
			trigger: `CREATE TRIGGER goauth_test_reject_notification_write
BEFORE INSERT ON auth_notification_deliveries FOR EACH ROW
EXECUTE FUNCTION goauth_test_reject_notification_write()`,
		},
		{
			name: "audit failure",
			trigger: `CREATE TRIGGER goauth_test_reject_notification_write
BEFORE INSERT ON auth_security_audit_events FOR EACH ROW
EXECUTE FUNCTION goauth_test_reject_notification_write()`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := integrationDB(t)
			runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
				func(context.Context, goauth.NotificationDelivery) error { return nil },
			))
			registered := register(t, runtime, "notification.rollback@example.test")
			_, err := db.Exec(`CREATE FUNCTION goauth_test_reject_notification_write()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'injected notification write failure';
END $$`)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, cleanupErr := db.Exec(`DROP FUNCTION IF EXISTS goauth_test_reject_notification_write() CASCADE`)
				require.NoError(t, cleanupErr)
			})
			_, err = db.Exec(test.trigger)
			require.NoError(t, err)

			err = runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
				goauth.EmailChallengePurposeVerification)
			require.ErrorContains(t, err, "injected notification write failure")

			var challenges, queued, audits, rateEvents int
			require.NoError(t, db.QueryRow(`
SELECT
    (SELECT count(*) FROM auth_email_challenges WHERE subject_id = $1),
    (SELECT count(*) FROM auth_notification_deliveries WHERE subject_id = $1),
    (SELECT count(*) FROM auth_security_audit_events
        WHERE subject_id = $1 AND event_type = 'email_challenge.issued'),
    (SELECT count(*) FROM auth_rate_limit_events
        WHERE subject_id = $1 AND action = 'email_challenge:verification')`,
				registered.Account.Subject.ID,
			).Scan(&challenges, &queued, &audits, &rateEvents))
			require.Zero(t, challenges)
			require.Zero(t, queued)
			require.Zero(t, audits)
			require.Zero(t, rateEvents)
		})
	}
}

func TestManagedNotificationDeliveryRetainsReceiptAndWrongCodeAttempt(t *testing.T) {
	db := integrationDB(t)
	deliveries := make(chan goauth.NotificationDelivery, 1)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, delivery goauth.NotificationDelivery) error {
			deliveries <- delivery
			return nil
		},
	))
	registered := register(t, runtime, "notification.delivery@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)
	stats, err := runtime.NotificationStats(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.Pending)
	require.NotNil(t, stats.OldestQueuedAt)
	require.False(t, stats.WorkerRunning)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	require.Error(t, store.DeleteEncrypted(context.Background(), id),
		"an unleased acknowledgement must not discard the notification")
	var ciphertext []byte
	require.NoError(t, db.QueryRow(`SELECT ciphertext FROM auth_notification_deliveries WHERE id = $1`, id).Scan(&ciphertext))
	require.NotEmpty(t, ciphertext)

	startManagedNotificationWorker(t, runtime)
	delivery := awaitManagedDelivery(t, deliveries)
	require.Equal(t, id, delivery.ID)
	require.Equal(t, id, delivery.EncryptedEvent.ID)
	require.Equal(t, ciphertext, delivery.EncryptedEvent.Envelope.Ciphertext)
	sealed, err := runtime.DecryptNotificationEvent(delivery.EncryptedEvent)
	require.NoError(t, err)
	require.Equal(t, delivery.Notification, sealed)
	require.Equal(t, "email_challenge", delivery.Notification.Template)
	require.Len(t, delivery.Notification.Data["code"], 6)
	require.True(t, delivery.ValidUntil.After(time.Now()))
	waitManagedNotificationState(t, db, id, "delivered")
	var deliveredAt sql.NullTime
	var ciphertextGone bool
	var nonceLength, additionalDataLength, attempts int
	require.NoError(t, db.QueryRow(`
SELECT delivered_at, ciphertext IS NULL, octet_length(nonce),
       octet_length(additional_data), attempts
FROM auth_notification_deliveries WHERE id = $1`, id).Scan(
		&deliveredAt, &ciphertextGone, &nonceLength, &additionalDataLength, &attempts,
	))
	require.True(t, deliveredAt.Valid)
	require.True(t, ciphertextGone)
	require.Zero(t, nonceLength)
	require.Zero(t, additionalDataLength)
	require.Equal(t, 1, attempts, "sender call is reserved before delivery")
	stats, err = runtime.NotificationStats(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.Delivered)
	require.True(t, stats.WorkerRunning)

	wrongCode := "000000"
	if delivery.Notification.Data["code"] == wrongCode {
		wrongCode = "999999"
	}
	_, err = runtime.VerifyEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification, wrongCode)
	require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	var challengeAttempts int
	require.NoError(t, db.QueryRow(`
SELECT attempts FROM auth_email_challenges WHERE subject_id = $1`,
		registered.Account.Subject.ID,
	).Scan(&challengeAttempts))
	require.Equal(t, 1, challengeAttempts)
}

func TestManagedNotificationRetryUsesStableDeliveryID(t *testing.T) {
	db := integrationDB(t)
	deliveries := make(chan goauth.NotificationDelivery, 2)
	var calls atomic.Int32
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, delivery goauth.NotificationDelivery) error {
			deliveries <- delivery
			if calls.Add(1) == 1 {
				return errors.New("temporary sender failure")
			}
			return nil
		},
	))
	registered := register(t, runtime, "notification.retry@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)

	startManagedNotificationWorker(t, runtime)
	first := awaitManagedDelivery(t, deliveries)
	second := awaitManagedDelivery(t, deliveries)
	waitManagedNotificationState(t, db, id, "delivered")
	require.Equal(t, id, first.ID)
	require.Equal(t, first.ID, second.ID, "the host must receive a stable idempotency key")
	require.EqualValues(t, 2, calls.Load())
	var attempts int
	require.NoError(t, db.QueryRow(`SELECT attempts FROM auth_notification_deliveries WHERE id = $1`, id).Scan(&attempts))
	require.Equal(t, 2, attempts)
}

func TestManagedNotificationRetryStartsAfterFailedSend(t *testing.T) {
	db := integrationDB(t)
	var firstCompleted, secondStarted time.Time
	var calls atomic.Int32
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, _ goauth.NotificationDelivery) error {
			if calls.Add(1) == 1 {
				time.Sleep(100 * time.Millisecond)
				firstCompleted = time.Now()
				return errors.New("slow sender failure")
			}
			secondStarted = time.Now()
			return nil
		},
	))
	registered := register(t, runtime, "notification.slow-retry@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)
	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, id, "delivered")
	require.EqualValues(t, 2, calls.Load())
	require.GreaterOrEqual(t, secondStarted.Sub(firstCompleted), 15*time.Millisecond)
}

func TestManagedNotificationResetInvalidatedByEmailChange(t *testing.T) {
	db := integrationDB(t)
	deliveries := make(chan goauth.NotificationDelivery, 3)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, delivery goauth.NotificationDelivery) error {
			deliveries <- delivery
			return nil
		},
	))
	const (
		oldEmail = "reset.old-address@example.test"
		newEmail = "reset.new-address@example.test"
	)
	registered := register(t, runtime, oldEmail)
	subjectID := registered.Account.Subject.ID
	require.NoError(t, runtime.RequestPasswordReset(context.Background(), oldEmail))
	resetID, reset := queuedNotification(t, db, subjectID, "password_reset")
	resetURL, err := url.Parse(reset.Data["reset_url"])
	require.NoError(t, err)
	resetToken := resetURL.Query().Get("token")
	require.NotEmpty(t, resetToken)
	require.NoError(t, runtime.RequestEmailChange(context.Background(), subjectID, newEmail))
	changeID, change := queuedNotification(t, db, subjectID, "email_change")
	_, err = runtime.ConfirmEmailChange(context.Background(), subjectID, change.Data["code"])
	require.NoError(t, err)
	require.ErrorIs(t, runtime.ResetPassword(context.Background(), resetToken, "Replacement-Passphrase-A1"),
		goauth.ErrResetAlreadyUsed)
	var consumed bool
	require.NoError(t, db.QueryRow(`SELECT consumed_at IS NOT NULL FROM auth_password_reset_records
WHERE subject_id = $1`, subjectID).Scan(&consumed))
	require.True(t, consumed)
	var changedID string
	require.NoError(t, db.QueryRow(`SELECT id FROM auth_notification_deliveries
WHERE subject_id = $1 AND event_type = 'email_changed'`, subjectID).Scan(&changedID))
	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, resetID, "expired")
	waitManagedNotificationState(t, db, changeID, "expired")
	waitManagedNotificationState(t, db, changedID, "delivered")
	select {
	case delivery := <-deliveries:
		require.Equal(t, changedID, delivery.ID)
		require.Equal(t, oldEmail, delivery.Notification.To)
	default:
		t.Fatal("email change confirmation was not delivered")
	}
	select {
	case delivery := <-deliveries:
		t.Fatalf("unexpected notification to old address: %s", delivery.ID)
	default:
	}
}

func TestManagedNotificationResetInvalidatedByPasswordAndStatusChange(t *testing.T) {
	for _, test := range []struct {
		name    string
		wantErr error
		change  func(*testing.T, *postgres.Runtime, goauth.SubjectID)
	}{
		{"password", goauth.ErrResetAlreadyUsed, func(t *testing.T, runtime *postgres.Runtime, subjectID goauth.SubjectID) {
			t.Helper()
			_, err := runtime.ChangePassword(context.Background(), goauth.ChangePasswordRequest{
				SubjectID: subjectID, CurrentPassword: "Integration-Unique-Passphrase-1",
				NewPassword: "Replacement-Passphrase-A1",
			})
			require.NoError(t, err)
		}},
		{"status", goauth.ErrInvalidToken, func(t *testing.T, runtime *postgres.Runtime, subjectID goauth.SubjectID) {
			t.Helper()
			_, err := runtime.SetSubjectStatus(context.Background(), subjectID, goauth.SubjectStatusDisabled)
			require.NoError(t, err)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := integrationDB(t)
			runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
				func(context.Context, goauth.NotificationDelivery) error { return nil },
			))
			registered := register(t, runtime, "reset."+test.name+"@example.test")
			subjectID := registered.Account.Subject.ID
			require.NoError(t, runtime.RequestPasswordReset(context.Background(), registered.Account.PrimaryEmail.DisplayValue))
			resetID, reset := queuedNotification(t, db, subjectID, "password_reset")
			resetURL, err := url.Parse(reset.Data["reset_url"])
			require.NoError(t, err)
			test.change(t, runtime, subjectID)
			require.ErrorIs(t, runtime.ResetPassword(context.Background(), resetURL.Query().Get("token"),
				"Another-Replacement-Passphrase-1"), test.wantErr)
			startManagedNotificationWorker(t, runtime)
			waitManagedNotificationState(t, db, resetID, "expired")
		})
	}
}

func TestPasswordResetIssueRejectsDisabledOrChangedSubject(t *testing.T) {
	db := integrationDB(t)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return nil },
	))
	registered := register(t, runtime, "reset.issue-guard@example.test")
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	record := goauth.PasswordResetRecord{
		SubjectID:               registered.Account.Subject.ID,
		Selector:                "stale-issue",
		Digest:                  goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{7}, 32)},
		ExpectedNormalizedEmail: registered.Account.PrimaryEmail.NormalizedValue,
		ExpectedSecurityVersion: registered.Account.Subject.SecurityVersion,
		CreatedAt:               time.Now().UTC(),
		ExpiresAt:               time.Now().UTC().Add(time.Minute),
	}
	_, err = runtime.SetSubjectStatus(context.Background(), record.SubjectID, goauth.SubjectStatusDisabled)
	require.NoError(t, err)
	require.ErrorIs(t, store.CreatePasswordReset(context.Background(), record), goauth.ErrAccountNotFound)
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_password_reset_records
WHERE selector = $1`, record.Selector).Scan(&count))
	require.Zero(t, count)
	_, err = runtime.SetSubjectStatus(context.Background(), record.SubjectID, goauth.SubjectStatusActive)
	require.NoError(t, err)
	require.ErrorIs(t, store.CreatePasswordReset(context.Background(), record), goauth.ErrAccountNotFound,
		"a stale security version must reject issuance even after reactivation")
}

func TestConcurrentPasswordResetIssuesLeaveOnlyOneActiveToken(t *testing.T) {
	db := integrationDB(t)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return nil },
	))
	registered := register(t, runtime, "reset.concurrent-issue@example.test")
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	base := goauth.PasswordResetRecord{
		SubjectID:               registered.Account.Subject.ID,
		Digest:                  goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{7}, 32)},
		ExpectedNormalizedEmail: registered.Account.PrimaryEmail.NormalizedValue,
		ExpectedSecurityVersion: registered.Account.Subject.SecurityVersion,
		CreatedAt:               time.Now().UTC(),
		ExpiresAt:               time.Now().UTC().Add(time.Minute),
	}
	start := make(chan struct{})
	errorsCh := make(chan error, 2)
	var workers sync.WaitGroup
	for _, selector := range []string{"concurrent-issue-a", "concurrent-issue-b"} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			record := base
			record.Selector = selector
			errorsCh <- store.CreatePasswordReset(context.Background(), record)
		}()
	}
	close(start)
	workers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		require.NoError(t, err)
	}
	var active int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_password_reset_records
WHERE subject_id = $1 AND consumed_at IS NULL`, base.SubjectID).Scan(&active))
	require.Equal(t, 1, active)
}

func TestManagedNotificationCleanupDuringSendDoesNotStopWorker(t *testing.T) {
	db := integrationDB(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, _ goauth.NotificationDelivery) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return nil
		},
	))
	first := register(t, runtime, "notification.cleanup-lease@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), first.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	firstID := managedNotificationID(t, db, first.Account.Subject.ID)
	startManagedNotificationWorker(t, runtime)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start the send")
	}
	policy := postgres.DefaultCleanupPolicy()
	policy.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	result, err := runtime.Cleanup(context.Background(), policy)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.NotificationsExpired)
	close(release)
	waitManagedNotificationState(t, db, firstID, "expired")
	second := register(t, runtime, "notification.after-cleanup@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), second.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	waitManagedNotificationState(t, db, managedNotificationID(t, db, second.Account.Subject.ID), "delivered")
}

func TestManagedNotificationSkipsStaleAndExpiredCodes(t *testing.T) {
	db := integrationDB(t)
	deliveries := make(chan goauth.NotificationDelivery, 1)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, delivery goauth.NotificationDelivery) error {
			deliveries <- delivery
			return nil
		},
	))
	staleAccount := register(t, runtime, "notification.stale@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), staleAccount.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	staleID := managedNotificationID(t, db, staleAccount.Account.Subject.ID)
	_, err := db.Exec(`
UPDATE auth_email_challenges SET created_at = created_at - interval '1 minute'
WHERE subject_id = $1`, staleAccount.Account.Subject.ID)
	require.NoError(t, err)
	_, err = db.Exec(`
DELETE FROM auth_rate_limit_events
WHERE subject_id = $1 AND action = 'email_challenge:verification'`, staleAccount.Account.Subject.ID)
	require.NoError(t, err)
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), staleAccount.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	currentID := managedNotificationID(t, db, staleAccount.Account.Subject.ID)
	require.NotEqual(t, staleID, currentID)

	expiredAccount := register(t, runtime, "notification.expired@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), expiredAccount.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	expiredID := managedNotificationID(t, db, expiredAccount.Account.Subject.ID)
	_, err = db.Exec(`
UPDATE auth_email_challenges SET expires_at = now() - interval '1 minute'
WHERE subject_id = $1`, expiredAccount.Account.Subject.ID)
	require.NoError(t, err)

	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, staleID, "expired")
	waitManagedNotificationState(t, db, expiredID, "expired")
	waitManagedNotificationState(t, db, currentID, "delivered")
	delivery := awaitManagedDelivery(t, deliveries)
	require.Equal(t, currentID, delivery.ID)
	select {
	case extra := <-deliveries:
		t.Fatalf("unexpected delivery of stale or expired notification %s", extra.ID)
	default:
	}
	for _, id := range []string{staleID, expiredID} {
		var ciphertextGone bool
		require.NoError(t, db.QueryRow(`
SELECT ciphertext IS NULL FROM auth_notification_deliveries WHERE id = $1`, id).Scan(&ciphertextGone))
		require.True(t, ciphertextGone)
	}
}

func TestManagedNotificationMissingKeyDoesNotBlockHealthyDelivery(t *testing.T) {
	db := integrationDB(t)
	deliveries := make(chan goauth.NotificationDelivery, 1)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, delivery goauth.NotificationDelivery) error {
			deliveries <- delivery
			return nil
		},
	))
	poisonedAccount := register(t, runtime, "notification.poisoned@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), poisonedAccount.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	poisonedID := managedNotificationID(t, db, poisonedAccount.Account.Subject.ID)
	_, err := db.Exec(`UPDATE auth_notification_deliveries SET key_id = 'missing-key' WHERE id = $1`, poisonedID)
	require.NoError(t, err)
	healthyAccount := register(t, runtime, "notification.healthy@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), healthyAccount.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	healthyID := managedNotificationID(t, db, healthyAccount.Account.Subject.ID)

	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, poisonedID, "blocked")
	waitManagedNotificationState(t, db, healthyID, "delivered")
	delivery := awaitManagedDelivery(t, deliveries)
	require.Equal(t, healthyID, delivery.ID)
	var failure string
	var ciphertextRetained bool
	require.NoError(t, db.QueryRow(`
SELECT last_failure, ciphertext IS NOT NULL
FROM auth_notification_deliveries WHERE id = $1`, poisonedID).Scan(&failure, &ciphertextRetained))
	require.Equal(t, "key_unavailable", failure)
	require.True(t, ciphertextRetained, "missing-key events must remain retryable after key restoration")
}

func TestManagedNotificationBlockedObserverKeepsQueueRunning(t *testing.T) {
	db := integrationDB(t)
	blocked := make(chan postgres.NotificationBlockedEvent, 1)
	deliveries := make(chan goauth.NotificationDelivery, 1)
	runtime := managedNotificationRuntimeWithWorker(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, delivery goauth.NotificationDelivery) error {
			deliveries <- delivery
			return nil
		}), postgres.NotificationWorkerConfig{
		PollInterval: 10 * time.Millisecond, SendTimeout: time.Second,
		LeaseDuration: 2 * time.Second, RetryMin: 20 * time.Millisecond,
		RetryMax: 50 * time.Millisecond, MaxAttempts: 3,
		OnBlocked: func(event postgres.NotificationBlockedEvent) { blocked <- event },
	})
	poisoned := register(t, runtime, "notification.observer-poisoned@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), poisoned.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	poisonedID := managedNotificationID(t, db, poisoned.Account.Subject.ID)
	_, err := db.Exec(`UPDATE auth_notification_deliveries SET key_id = 'missing-key' WHERE id = $1`, poisonedID)
	require.NoError(t, err)
	healthy := register(t, runtime, "notification.observer-healthy@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), healthy.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	healthyID := managedNotificationID(t, db, healthy.Account.Subject.ID)
	startManagedNotificationWorker(t, runtime)
	select {
	case event := <-blocked:
		require.Equal(t, postgres.NotificationBlockedEvent{DeliveryID: poisonedID, Reason: "key_unavailable"}, event)
	case <-time.After(5 * time.Second):
		t.Fatal("blocked delivery was not reported")
	}
	waitManagedNotificationState(t, db, poisonedID, "blocked")
	waitManagedNotificationState(t, db, healthyID, "delivered")
	require.Equal(t, healthyID, awaitManagedDelivery(t, deliveries).ID)
	var attempts int
	require.NoError(t, db.QueryRow(`SELECT attempts FROM auth_notification_deliveries WHERE id = $1`, poisonedID).Scan(&attempts))
	require.Zero(t, attempts, "decrypt failure must not spend a sender call")
}

func TestManagedNotificationSendBudgetSurvivesLeaseTakeover(t *testing.T) {
	db := integrationDB(t)
	var calls atomic.Int32
	var cancelCurrent context.CancelFunc
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error {
			calls.Add(1)
			cancelCurrent() // Simulate a process stopping after the provider call.
			return nil
		}))
	registered := register(t, runtime, "notification.crash-budget@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)
	for range 3 {
		ctx, cancel := context.WithCancel(context.Background())
		cancelCurrent = cancel
		result := make(chan error, 1)
		go func() { result <- runtime.RunNotifications(ctx) }()
		select {
		case <-result:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("worker did not stop after simulated crash")
		}
		_, err := db.Exec(`UPDATE auth_notification_deliveries SET leased_until = now() - interval '1 second' WHERE id = $1`, id)
		require.NoError(t, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runtime.RunNotifications(ctx) }()
	waitManagedNotificationState(t, db, id, "exhausted")
	cancel()
	<-result
	require.EqualValues(t, 3, calls.Load())
	var attempts int
	require.NoError(t, db.QueryRow(`SELECT attempts FROM auth_notification_deliveries WHERE id = $1`, id).Scan(&attempts))
	require.Equal(t, 3, attempts)
}

func TestManagedNotificationSkipsOldVerificationAndDisabledSubjects(t *testing.T) {
	for _, scenario := range []string{"changed_email", "disabled_challenge", "disabled_change"} {
		t.Run(scenario, func(t *testing.T) {
			db := integrationDB(t)
			deliveries := make(chan goauth.NotificationDelivery, 4)
			runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
				func(_ context.Context, delivery goauth.NotificationDelivery) error {
					deliveries <- delivery
					return nil
				}))
			registered := register(t, runtime, "notification-stale-"+scenario+"@example.test")
			subjectID := registered.Account.Subject.ID
			require.NoError(t, runtime.SendEmailChallenge(context.Background(), subjectID,
				goauth.EmailChallengePurposeVerification))
			challengeID := managedNotificationID(t, db, subjectID)
			var changeID string
			if scenario == "changed_email" || scenario == "disabled_change" {
				require.NoError(t, runtime.RequestEmailChange(context.Background(), subjectID,
					"notification-new-"+scenario+"@example.test"))
				var change goauth.Notification
				changeID, change = queuedNotification(t, db, subjectID, "email_change")
				if scenario == "changed_email" {
					_, err := runtime.ConfirmEmailChange(context.Background(), subjectID, change.Data["code"])
					require.NoError(t, err)
				}
			}
			if scenario != "changed_email" {
				_, err := runtime.SetSubjectStatus(context.Background(), subjectID, goauth.SubjectStatusDisabled)
				require.NoError(t, err)
			} else {
				var attempts, maxAttempts int
				require.NoError(t, db.QueryRow(`
SELECT attempts, max_attempts FROM auth_email_challenges
WHERE subject_id = $1 ORDER BY created_at DESC LIMIT 1`, subjectID).Scan(&attempts, &maxAttempts))
				require.Equal(t, maxAttempts, attempts, "old verification code must be invalidated")
			}
			startManagedNotificationWorker(t, runtime)
			waitManagedNotificationState(t, db, challengeID, "expired")
			if changeID != "" {
				waitManagedNotificationState(t, db, changeID, "expired")
			}
			select {
			case delivery := <-deliveries:
				require.NotEqual(t, challengeID, delivery.ID)
				require.NotEqual(t, changeID, delivery.ID)
			default:
			}
		})
	}
}

func TestEmailChallengeIssuanceRejectsStaleEmailSnapshot(t *testing.T) {
	db := integrationDB(t)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return nil }))
	registered := register(t, runtime, "stale-issue-old@example.test")
	oldAccount := registered.Account
	subjectID := oldAccount.Subject.ID
	require.NoError(t, runtime.RequestEmailChange(context.Background(), subjectID, "stale-issue-new@example.test"))
	_, change := queuedNotification(t, db, subjectID, "email_change")
	_, err := runtime.ConfirmEmailChange(context.Background(), subjectID, change.Data["code"])
	require.NoError(t, err)

	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	now := time.Now().UTC()
	_, err = store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{
		ID:                      goauth.NewSubjectID().String(),
		SubjectID:               subjectID,
		IdentifierID:            oldAccount.PrimaryEmail.ID,
		ExpectedNormalizedEmail: oldAccount.PrimaryEmail.NormalizedValue,
		ExpectedSecurityVersion: oldAccount.Subject.SecurityVersion,
		Purpose:                 goauth.EmailChallengePurposeVerification,
		Digest:                  goauth.SecretDigest{KeyID: "test-key", Digest: make([]byte, 32)},
		RateDigest:              goauth.SecretDigest{KeyID: "rate-key", Digest: make([]byte, 32)},
		MaxAttempts:             5,
		CreatedAt:               now,
		ExpiresAt:               now.Add(time.Hour),
	}, goauth.EmailChallengeLimits{MinResendInterval: time.Minute, PerHour: 5, PerDay: 10})
	require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
	var challenges int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_email_challenges WHERE subject_id = $1`,
		subjectID).Scan(&challenges))
	require.Zero(t, challenges, "a code for a stale destination must not be persisted")
}

func TestManagedNotificationRetriesAfterKeyRecovery(t *testing.T) {
	db := integrationDB(t)
	deliveries := make(chan goauth.NotificationDelivery, 1)
	sender := goauth.NotificationSenderFunc(func(_ context.Context, delivery goauth.NotificationDelivery) error {
		deliveries <- delivery
		return nil
	})
	issuer := managedNotificationRuntime(t, db, sender)
	registered := register(t, issuer, "notification.key-recovery@example.test")
	require.NoError(t, issuer.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)

	missingConfig := runtimeConfig(t)
	missingConfig.EventSink = nil
	missingConfig.OutboxAEADKeys = keyRing(t, "outbox-new", 4)
	missingKeyRuntime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: missingConfig, NotificationSender: sender,
		NotificationWorker: postgres.NotificationWorkerConfig{PollInterval: 10 * time.Millisecond},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- missingKeyRuntime.RunNotifications(ctx) }()
	waitManagedNotificationState(t, db, id, "blocked")
	cancel()
	require.NoError(t, <-done)

	recoveredConfig := runtimeConfig(t)
	recoveredConfig.EventSink = nil
	recoveredConfig.OutboxAEADKeys, err = goauth.NewKeyRing("outbox-new-v1",
		goauth.Key{ID: "outbox-v1", Material: bytes.Repeat([]byte{3}, 32)},
		goauth.Key{ID: "outbox-new-v1", Material: bytes.Repeat([]byte{4}, 32)})
	require.NoError(t, err)
	recovered, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: recoveredConfig, NotificationSender: sender,
		NotificationWorker: postgres.NotificationWorkerConfig{PollInterval: 10 * time.Millisecond},
	})
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE auth_notification_deliveries SET next_attempt_at = now() WHERE id = $1`, id)
	require.NoError(t, err)
	startManagedNotificationWorker(t, recovered)
	delivery := awaitManagedDelivery(t, deliveries)
	require.Equal(t, id, delivery.ID)
	waitManagedNotificationState(t, db, id, "delivered")
}

func TestManagedNotificationLeaseIsExclusiveAcrossRuntimes(t *testing.T) {
	db := integrationDB(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	sender := goauth.NotificationSenderFunc(func(ctx context.Context, _ goauth.NotificationDelivery) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	first := managedNotificationRuntime(t, db, sender)
	registered := register(t, first, "notification.lease@example.test")
	require.NoError(t, first.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)
	config := runtimeConfig(t)
	config.EventSink = nil
	second, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: sender,
		NotificationWorker: postgres.NotificationWorkerConfig{PollInterval: 10 * time.Millisecond},
	})
	require.NoError(t, err)
	startManagedNotificationWorker(t, first)
	startManagedNotificationWorker(t, second)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no worker claimed the notification")
	}
	select {
	case <-entered:
		t.Fatal("two runtimes delivered the same active lease")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	waitManagedNotificationState(t, db, id, "delivered")
}

func TestManagedNotificationCleanupWithoutWorkerRemovesExpiredCiphertext(t *testing.T) {
	db := integrationDB(t)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return nil },
	))
	registered := register(t, runtime, "notification.cleanup@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, registered.Account.Subject.ID)
	policy := postgres.DefaultCleanupPolicy()
	policy.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	result, err := runtime.Cleanup(context.Background(), policy)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.NotificationsExpired)
	var state string
	var ciphertextGone bool
	require.NoError(t, db.QueryRow(`
SELECT state, ciphertext IS NULL FROM auth_notification_deliveries WHERE id = $1`, id).Scan(&state, &ciphertextGone))
	require.Equal(t, "expired", state)
	require.True(t, ciphertextGone)
	stats, err := runtime.NotificationStats(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, stats.Expired)
	require.False(t, stats.WorkerRunning)
}

func TestManagedNotificationSkipsConsumedResetAndEmailChange(t *testing.T) {
	db := integrationDB(t)
	deliveries := make(chan goauth.NotificationDelivery, 2)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(
		func(_ context.Context, delivery goauth.NotificationDelivery) error {
			deliveries <- delivery
			return nil
		},
	))
	registered := register(t, runtime, "notification.consumed@example.test")
	require.NoError(t, runtime.RequestPasswordReset(context.Background(),
		registered.Account.PrimaryEmail.DisplayValue))
	require.NoError(t, runtime.RequestEmailChange(context.Background(),
		registered.Account.Subject.ID, "notification.changed@example.test"))
	var resetID, changeID string
	require.NoError(t, db.QueryRow(`SELECT id FROM auth_notification_deliveries
WHERE event_type = 'password_reset'`).Scan(&resetID))
	require.NoError(t, db.QueryRow(`SELECT id FROM auth_notification_deliveries
WHERE event_type = 'email_change'`).Scan(&changeID))
	_, err := db.Exec(`UPDATE auth_password_reset_records SET consumed_at = now()
WHERE subject_id = $1`, registered.Account.Subject.ID)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE auth_email_change_records SET consumed_at = now()
WHERE subject_id = $1`, registered.Account.Subject.ID)
	require.NoError(t, err)
	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, resetID, "expired")
	waitManagedNotificationState(t, db, changeID, "expired")
	select {
	case delivery := <-deliveries:
		t.Fatalf("unexpected delivery of consumed code %s", delivery.ID)
	default:
	}
}

func managedNotificationRuntime(t *testing.T, db *sql.DB, sender goauth.NotificationSender) *postgres.Runtime {
	return managedNotificationRuntimeWithWorker(t, db, sender, postgres.NotificationWorkerConfig{
		PollInterval: 10 * time.Millisecond, SendTimeout: time.Second,
		LeaseDuration: 2 * time.Second, RetryMin: 20 * time.Millisecond,
		RetryMax: 50 * time.Millisecond, MaxAttempts: 3,
	})
}

func managedNotificationRuntimeWithWorker(t *testing.T, db *sql.DB, sender goauth.NotificationSender, worker postgres.NotificationWorkerConfig) *postgres.Runtime {
	t.Helper()
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	config := runtimeConfig(t)
	config.EventSink = nil
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB:                 db,
		Runtime:            config,
		NotificationSender: sender,
		NotificationWorker: worker,
	})
	require.NoError(t, err)
	return runtime
}

func managedNotificationID(t *testing.T, db *sql.DB, subjectID goauth.SubjectID) string {
	t.Helper()
	var id string
	require.NoError(t, db.QueryRow(`
SELECT id FROM auth_notification_deliveries
WHERE subject_id = $1 AND event_type = 'email_challenge'
ORDER BY created_at DESC LIMIT 1`, subjectID).Scan(&id))
	return id
}

func queuedNotification(t *testing.T, db *sql.DB, subjectID goauth.SubjectID, eventType string) (string, goauth.Notification) {
	t.Helper()
	var id string
	var envelope goauth.EncryptedEnvelope
	require.NoError(t, db.QueryRow(`
SELECT id, key_id, nonce, ciphertext, additional_data, created_at, delete_after
FROM auth_notification_deliveries
WHERE subject_id = $1 AND event_type = $2
ORDER BY created_at DESC LIMIT 1`, subjectID, eventType).Scan(
		&id, &envelope.KeyID, &envelope.Nonce, &envelope.Ciphertext,
		&envelope.AdditionalData, &envelope.CreatedAt, &envelope.DeleteAfter,
	))
	notification, err := testkit.DecryptNotification(runtimeConfig(t).OutboxAEADKeys, envelope)
	require.NoError(t, err)
	return id, notification
}

func startManagedNotificationWorker(t *testing.T, runtime *postgres.Runtime) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.RunNotifications(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Error("managed notification worker did not stop")
		}
	})
}

func waitManagedNotificationState(t *testing.T, db *sql.DB, id, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var state string
		return db.QueryRow(`SELECT state FROM auth_notification_deliveries WHERE id = $1`, id).Scan(&state) == nil && state == want
	}, 5*time.Second, 10*time.Millisecond, "notification %s did not reach state %s", id, want)
}

func awaitManagedDelivery(t *testing.T, deliveries <-chan goauth.NotificationDelivery) goauth.NotificationDelivery {
	t.Helper()
	select {
	case delivery := <-deliveries:
		return delivery
	case <-time.After(5 * time.Second):
		t.Fatal("managed notification sender was not called")
		return goauth.NotificationDelivery{}
	}
}

func TestManagedNotificationRenewsLeaseBeforeSending(t *testing.T) {
	for _, claimAge := range []time.Duration{1500 * time.Millisecond, 3 * time.Second} {
		t.Run(claimAge.String(), func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			remaining := make(chan time.Duration, 1)
			config := runtimeConfig(t)
			config.EventSink = nil
			var armed, aged atomic.Bool
			config.Now = func() time.Time {
				now := time.Now()
				if armed.Load() && aged.CompareAndSwap(false, true) {
					return now.Add(-claimAge)
				}
				return now
			}
			runtime, err := postgres.NewRuntime(postgres.Config{
				DB: db, Runtime: config,
				NotificationWorker: postgres.NotificationWorkerConfig{
					PollInterval: 10 * time.Millisecond,
					SendTimeout:  time.Second, LeaseDuration: 2 * time.Second,
				},
				NotificationSender: goauth.NotificationSenderFunc(func(ctx context.Context, delivery goauth.NotificationDelivery) error {
					var leaseUntil time.Time
					if err := db.QueryRowContext(ctx, `SELECT leased_until FROM auth_notification_deliveries WHERE id = $1`, delivery.ID).Scan(&leaseUntil); err != nil {
						return err
					}
					remaining <- time.Until(leaseUntil)
					return nil
				}),
			})
			require.NoError(t, err)
			registered := register(t, runtime, "renew.lease@example.test")
			require.NoError(t, runtime.SendEmailChallenge(t.Context(), registered.Account.Subject.ID, goauth.EmailChallengePurposeVerification))
			id := managedNotificationID(t, db, registered.Account.Subject.ID)
			armed.Store(true)
			startManagedNotificationWorker(t, runtime)
			select {
			case leaseRemaining := <-remaining:
				require.Greater(t, leaseRemaining, time.Second, "claim preparation must not consume the sender's lease budget")
			case <-time.After(5 * time.Second):
				t.Fatal("notification was not delivered")
			}
			waitManagedNotificationState(t, db, id, "delivered")
			var attempts int
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT attempts FROM auth_notification_deliveries WHERE id = $1`, id).Scan(&attempts))
			require.Equal(t, 1, attempts, "expired claims must be reclaimed before reserving a send")
		})
	}
}
