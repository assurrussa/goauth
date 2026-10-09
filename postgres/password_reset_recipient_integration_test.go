//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

type postgresResetRecipientPolicy struct {
	subject goauth.SubjectID
	address atomic.Value
	denied  atomic.Bool
}

func (p *postgresResetRecipientPolicy) LookupPasswordResetSubject(context.Context, string) (goauth.SubjectID, error) {
	if p.denied.Load() {
		return goauth.SubjectID{}, goauth.ErrAccountNotFound
	}
	return p.subject, nil
}

func (p *postgresResetRecipientPolicy) ResolvePasswordResetRecipient(_ context.Context, account goauth.Account, requested string) (string, error) {
	address, ok := p.address.Load().(string)
	if !ok {
		return "", goauth.ErrAccountNotFound
	}
	if p.denied.Load() || account.Subject.ID != p.subject ||
		(requested != "" && requested != address && requested != account.PrimaryEmail.NormalizedValue) {
		return "", goauth.ErrAccountNotFound
	}
	return address, nil
}

func postgresRecipientAddress(t *testing.T, policy *postgresResetRecipientPolicy) string {
	t.Helper()
	address, ok := policy.address.Load().(string)
	require.True(t, ok)
	return address
}

func recipientPostgresRuntime(t *testing.T, sender goauth.NotificationSender) (*postgres.Runtime, *sql.DB, *postgresResetRecipientPolicy) {
	t.Helper()
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	policy := &postgresResetRecipientPolicy{}
	policy.address.Store("host-recovery@example.test")
	config := runtimeConfig(t)
	config.EventSink = nil
	config.PasswordResetRecipientResolver = policy
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: sender,
		NotificationWorker: postgres.NotificationWorkerConfig{
			PollInterval: 10 * time.Millisecond, SendTimeout: time.Second,
			LeaseDuration: 2 * time.Second, RetryMin: 10 * time.Millisecond, RetryMax: time.Second,
		},
	})
	require.NoError(t, err)
	registered := register(t, runtime, "canonical-primary@example.test")
	policy.subject = registered.Account.Subject.ID
	return runtime, db, policy
}

func TestPostgresRecipientInvalidationJoinsHostTransaction(t *testing.T) {
	runtime, db, policy := recipientPostgresRuntime(t, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return nil },
	))
	require.NoError(t, runtime.RequestPasswordReset(t.Context(), postgresRecipientAddress(t, policy)))
	_, notification := queuedNotification(t, db, policy.subject, "password_reset")
	resetURL, err := url.Parse(notification.Data["reset_url"])
	require.NoError(t, err)
	token := resetURL.Query().Get("token")
	rollback := errors.New("rollback host alias mutation")
	require.ErrorIs(t, runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		require.NoError(t, runtime.InvalidatePasswordResets(ctx, policy.subject))
		return rollback
	}), rollback)
	var pending int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_password_reset_records WHERE subject_id=$1 AND consumed_at IS NULL`,
		policy.subject).Scan(&pending))
	require.Equal(t, 1, pending)
	require.NoError(t, runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		return runtime.InvalidatePasswordResets(ctx, policy.subject)
	}))
	// Restoring the exact recipient never revives the consumed record.
	policy.address.Store("away@example.test")
	policy.address.Store("host-recovery@example.test")
	require.ErrorIs(t, runtime.ResetPassword(t.Context(), token, "Replacement-Recipient-Passphrase-42"), goauth.ErrResetAlreadyUsed)
}

func TestPostgresQueuedResetAndSuccessRevalidateRecipient(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "reset", true: "success"}[success], func(t *testing.T) {
			var sends atomic.Int64
			runtime, db, policy := recipientPostgresRuntime(t, goauth.NotificationSenderFunc(
				func(context.Context, goauth.NotificationDelivery) error { sends.Add(1); return nil },
			))
			require.NoError(t, runtime.RequestPasswordReset(t.Context(), postgresRecipientAddress(t, policy)))
			id, notification := queuedNotification(t, db, policy.subject, "password_reset")
			if success {
				resetURL, err := url.Parse(notification.Data["reset_url"])
				require.NoError(t, err)
				require.NoError(t, runtime.ResetPassword(t.Context(), resetURL.Query().Get("token"), "Replacement-Recipient-Passphrase-42"))
				id, _ = queuedNotification(t, db, policy.subject, "password_reset_success")
			}
			// Deliberately omit invalidation here to isolate the worker recipient guard.
			policy.address.Store("changed-recovery@example.test")
			startManagedNotificationWorker(t, runtime)
			waitManagedNotificationState(t, db, id, "expired")
			require.Zero(t, sends.Load())
		})
	}
}

func TestPostgresRecipientSenderHoldsCanonicalSubjectLock(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var runtime *postgres.Runtime
	sender := goauth.NotificationSenderFunc(func(ctx context.Context, _ goauth.NotificationDelivery) error {
		err := runtime.InOwnedAuthTransaction(ctx, func(context.Context) error {
			return errors.New("nested owned transaction callback ran")
		})
		if !errors.Is(err, postgres.ErrAuthTransactionAlreadyActive) {
			return errors.New("recipient sender did not receive the managed transaction")
		}
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	var db *sql.DB
	var policy *postgresResetRecipientPolicy
	runtime, db, policy = recipientPostgresRuntime(t, sender)
	require.NoError(t, runtime.RequestPasswordReset(t.Context(), postgresRecipientAddress(t, policy)))
	id, _ := queuedNotification(t, db, policy.subject, "password_reset")
	startManagedNotificationWorker(t, runtime)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("recipient sender was not called")
	}
	changed := make(chan error, 1)
	go func() { changed <- runtime.InvalidatePasswordResets(context.Background(), policy.subject) }()
	select {
	case err := <-changed:
		close(release)
		t.Fatalf("alias invalidation escaped the sender subject lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-changed:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("alias invalidation did not resume")
	}
	waitManagedNotificationState(t, db, id, "delivered")
}

func TestPostgresSubjectResetStoreDoesNotProvisionCredential(t *testing.T) {
	runtime, db, policy := recipientPostgresRuntime(t, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return nil },
	))
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	account, err := runtime.GetAccount(t.Context(), policy.subject)
	require.NoError(t, err)
	now := time.Now().UTC()
	record := goauth.PasswordResetRecord{
		SubjectID: policy.subject, Selector: "subject-reset-store",
		Digest:                  goauth.SecretDigest{KeyID: "test", Digest: make([]byte, 32)},
		ExpectedSecurityVersion: account.Subject.SecurityVersion, CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
	stale := record
	stale.ExpectedSecurityVersion++
	require.ErrorIs(t, store.CreatePasswordResetForSubject(t.Context(), stale), goauth.ErrAccountNotFound)
	require.NoError(t, store.CreatePasswordResetForSubject(t.Context(), record))
	_, err = db.Exec(`DELETE FROM auth_local_credentials WHERE subject_id=$1`, policy.subject)
	require.NoError(t, err)
	record.Selector = "missing-local-credential"
	require.ErrorIs(t, store.CreatePasswordResetForSubject(t.Context(), record), goauth.ErrAccountNotFound)
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_local_credentials WHERE subject_id=$1`, policy.subject).Scan(&count))
	require.Zero(t, count)
}

func (p *postgresResetRecipientPolicy) PreparePasswordResetPassword(context.Context, goauth.Account, string) (string, error) {
	return "", nil
}

func TestPostgresPreparedConsumeSharesDirectStoreTransaction(t *testing.T) {
	runtime, db, policy := recipientPostgresRuntime(t, goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error { return nil },
	))
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	account, err := runtime.GetAccount(t.Context(), policy.subject)
	require.NoError(t, err)
	now := time.Now().UTC()
	record := goauth.PasswordResetRecord{
		SubjectID: policy.subject, Selector: "direct-prepared-reset",
		Digest:                  goauth.SecretDigest{KeyID: "test", Digest: make([]byte, 32)},
		ExpectedSecurityVersion: account.Subject.SecurityVersion, CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
	require.NoError(t, store.CreatePasswordResetForSubject(t.Context(), record))
	previousLimit := db.Stats().MaxOpenConnections
	db.SetMaxOpenConns(1)
	defer db.SetMaxOpenConns(previousLimit)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	called := false
	result, err := store.ConsumePasswordResetWithPreparation(ctx, goauth.PasswordResetConsumeRequest{
		Selector: record.Selector, Digest: record.Digest, Now: now,
	}, func(txCtx context.Context, account goauth.Account) (string, error) {
		called = true
		local, err := store.GetLocalAccount(txCtx, account.Subject.ID)
		if err != nil {
			return "", err
		}
		return local.PasswordPHC, nil
	})
	require.NoError(t, err)
	require.True(t, called)
	require.Equal(t, goauth.PasswordResetConsumed, result.Status)
	require.Equal(t, policy.subject, result.Account.Subject.ID)
}
