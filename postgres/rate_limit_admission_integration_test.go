//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

const admissionTestPassword = "Admission-Unique-Passphrase-42" //nolint:gosec // Isolated fixture credential.

func TestPostgresReviewNestedChangePasswordMultiAndSingleConn(t *testing.T) {
	for _, connections := range []int{1, 4} {
		t.Run(map[int]string{1: "single_conn", 4: "multi_conn"}[connections], func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			db.SetMaxOpenConns(connections)
			defer db.SetMaxOpenConns(0)
			config := runtimeConfig(t)
			config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Hour, Limit: 1}
			makeRuntime := func() *postgres.Runtime {
				t.Helper()
				runtime, err := postgres.NewRuntime(postgres.Config{
					DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
				})
				require.NoError(t, err)
				return runtime
			}
			auth := makeRuntime()
			account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
				Email: "boundary@example.test", Password: admissionTestPassword,
			})
			require.NoError(t, err)
			store, err := postgres.NewStore(db)
			require.NoError(t, err)
			before, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			request := goauth.ChangePasswordRequest{
				SubjectID: account.Subject.ID, CurrentPassword: admissionTestPassword,
				NewPassword: "New-Unique-Passphrase-42",
			}
			for _, password := range []string{request.CurrentPassword, "incorrect-review-password"} {
				request.CurrentPassword = password
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				err = store.InAuthTransaction(ctx, func(txCtx context.Context) error {
					if _, err := store.LockAccount(txCtx, account.Subject.ID); err != nil {
						return err
					}
					_, err := auth.ChangePassword(txCtx, request)
					return err
				})
				cancel()
				require.ErrorIs(t, err, goauth.ErrRateLimitTransactionUnsupported)
			}
			after, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, before, after)
			var attempts, notifications, audits int
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT
    (SELECT count(*) FROM auth_rate_limit_events WHERE action = 'password_change'),
    (SELECT count(*) FROM auth_notification_deliveries WHERE event_type = 'password_changed'),
    (SELECT count(*) FROM auth_security_audit_events WHERE event_type = $1)`,
				string(goauth.SecurityEventPasswordChanged)).Scan(
				&attempts, &notifications, &audits))
			require.Zero(t, attempts)
			require.Zero(t, notifications)
			require.Zero(t, audits)
			// Standalone admission persists before verification. A fresh Runtime
			// (with its own Store) must see the failed attempt without a memory cache.
			_, err = auth.ChangePassword(t.Context(), request)
			require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
			_, err = makeRuntime().ChangePassword(t.Context(), request)
			require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
			require.NoError(t, db.QueryRowContext(t.Context(),
				`SELECT count(*) FROM auth_rate_limit_events WHERE action = 'password_change'`).Scan(&attempts))
			require.Equal(t, 1, attempts)
		})
	}
}

func TestPostgresRateAdmissionCountsEqualTimestampsAcrossStores(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	request := goauth.RateLimitRequest{
		Action: "equal_timestamps", Bucket: goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{7}, 32)},
		Window: time.Hour, Limit: 2, Now: time.Date(2026, 9, 29, 12, 0, 0, 123456789, time.UTC),
	}
	for _, allowed := range []bool{true, true, false} {
		store, err := postgres.NewStore(db)
		require.NoError(t, err)
		result, err := store.TakeRateLimit(t.Context(), request)
		require.NoError(t, err)
		require.Equal(t, allowed, result.Allowed)
	}
	var count int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM auth_rate_limit_events WHERE action = 'equal_timestamps'`).Scan(&count))
	require.Equal(t, 2, count)
}

func TestPostgresReviewAuthenticationRateLimitReducedWindow(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	request := goauth.RateLimitRequest{
		Action: "test_reduced_login", Bucket: goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{7}, 32)},
		Window: time.Hour, Limit: 10,
	}
	for i := range 5 {
		request.Now = base.Add(time.Duration(i) * time.Minute)
		result, err := store.TakeRateLimit(t.Context(), request)
		require.NoError(t, err)
		require.True(t, result.Allowed)
	}
	request.Limit = 2
	deadline := base.Add(63 * time.Minute)
	for _, at := range []time.Time{base.Add(59 * time.Minute), deadline.Add(-time.Second), deadline} {
		request.Now = at
		result, err := store.TakeRateLimit(t.Context(), request)
		require.NoError(t, err)
		require.False(t, result.Allowed)
		require.True(t, deadline.Equal(result.RetryAt))
	}
	request.Now = deadline.Add(time.Second)
	result, err := store.TakeRateLimit(t.Context(), request)
	require.NoError(t, err)
	require.True(t, result.Allowed)
}

// Retains the previously added PostgreSQL parity coverage while admission tests
// adopt the explicit no-outer-transaction contract.
func TestPostgresReviewEmailInvalidationTiming(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	now := time.Now().UTC()
	config := runtimeConfig(t)
	config.Now = func() time.Time { return now }
	auth, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "email.timing@example.test", Password: admissionTestPassword,
	})
	require.NoError(t, err)
	id := account.Subject.ID
	_, err = auth.Login(t.Context(), goauth.LoginRequest{
		Realm: goauth.RealmUser, Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "email.timing@example.test"},
			Password:   admissionTestPassword,
		},
	})
	require.NoError(t, err)
	require.NoError(t, auth.RequestEmailChange(t.Context(), id, "new1@example.test"))
	err = store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		count, err := auth.LogoutAll(ctx, id)
		if err != nil {
			return err
		}
		require.EqualValues(t, 1, count)
		_, err = auth.ConfirmEmailChange(ctx, id, "000000")
		require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
		return nil
	})
	require.NoError(t, err)
	now = now.Add(2 * time.Minute)
	err = store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		if _, err := auth.LogoutAll(ctx, id); err != nil {
			return err
		}
		return auth.RequestEmailChange(ctx, id, "new2@example.test")
	})
	require.NoError(t, err)
	pending, err := auth.PendingEmailChange(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, "new2@example.test", pending.NewDisplayValue)
	now = now.Add(2 * time.Minute)
	require.NoError(t, auth.RequestEmailChange(t.Context(), id, "new3@example.test"))
	_, err = store.RevokeSubjectSessions(t.Context(), id, now.Add(time.Second))
	require.NoError(t, err)
	_, err = auth.PendingEmailChange(t.Context(), id)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}
