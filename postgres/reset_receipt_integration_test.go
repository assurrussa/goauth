//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestResetReceiptBindsAtomicallyAcrossClockSkewAndConcurrentReset(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config,
		NotificationSender: goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error { return nil }),
	})
	require.NoError(t, err)
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "receipt-binding@example.test", Password: "Integration-Receipt-Passphrase-1",
	})
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "CREATE TABLE goauth_reset_receipt_probe (selector text PRIMARY KEY, bound_at timestamptz DEFAULT now())")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE goauth_reset_receipt_probe") })
	rejected := errors.New("projection rejected")
	bind := func(ctx context.Context, receipt goauth.PasswordResetReceipt) error {
		if receipt.SubjectID != account.Subject.ID {
			return errors.New("unexpected receipt subject")
		}
		executor, err := runtime.SQLExecutor(ctx)
		if err != nil {
			return err
		}
		_, err = executor.ExecContext(ctx, "INSERT INTO goauth_reset_receipt_probe(selector) VALUES ($1)", receipt.Selector)
		return err
	}
	err = runtime.RequestPasswordResetWithReceipt(t.Context(), account.PrimaryEmail.DisplayValue,
		func(ctx context.Context, receipt goauth.PasswordResetReceipt) error {
			if err := bind(ctx, receipt); err != nil {
				return err
			}
			return rejected
		})
	require.ErrorIs(t, err, rejected)
	var resets, queued, audits, projections int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT
  (SELECT count(*) FROM auth_password_reset_records),
  (SELECT count(*) FROM auth_notification_deliveries),
  (SELECT count(*) FROM auth_security_audit_events WHERE event_type='password_reset.issued'),
  (SELECT count(*) FROM goauth_reset_receipt_probe)`).Scan(&resets, &queued, &audits, &projections))
	require.Zero(t, resets)
	require.Zero(t, queued)
	require.Zero(t, audits)
	require.Zero(t, projections)
	results := make(chan error, 2)
	start := make(chan struct{})
	go func() {
		<-start
		results <- runtime.RequestPasswordReset(t.Context(), account.PrimaryEmail.DisplayValue)
	}()
	go func() {
		<-start
		results <- runtime.RequestPasswordResetWithReceipt(t.Context(), account.PrimaryEmail.DisplayValue, bind)
	}()
	close(start)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	var exact, ordinary int
	var skew time.Duration
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT
  (SELECT count(*) FROM auth_password_reset_records r JOIN goauth_reset_receipt_probe p USING(selector)),
  (SELECT count(*) FROM auth_password_reset_records r WHERE NOT EXISTS
   (SELECT 1 FROM goauth_reset_receipt_probe p WHERE p.selector=r.selector)),
  (SELECT (extract(epoch from (p.bound_at-r.created_at))*1000000000)::bigint
   FROM auth_password_reset_records r JOIN goauth_reset_receipt_probe p USING(selector))`).Scan(&exact, &ordinary, &skew))
	require.Equal(t, 1, exact)
	require.Equal(t, 1, ordinary)
	require.Greater(t, skew, 30*time.Minute)
	called := false
	require.NoError(t, runtime.RequestPasswordResetWithReceipt(t.Context(), "absent@example.test",
		func(context.Context, goauth.PasswordResetReceipt) error { called = true; return nil }))
	require.False(t, called)
}
