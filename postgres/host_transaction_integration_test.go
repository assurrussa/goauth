//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
)

func TestDisabledDeliverySharedHostTransaction(t *testing.T) {
	testDisabledDeliverySharedHostTransaction(t, false)
}

func TestOwnedAuthTransactionCanonicalHostAtomicity(t *testing.T) {
	testDisabledDeliverySharedHostTransaction(t, true)
}

func testDisabledDeliverySharedHostTransaction(t *testing.T, owned bool) {
	t.Helper()
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	config.OutboxAEADKeys = goauth.KeyRing{}
	config.URLBuilder = nil
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	require.Same(t, db, runtime.Database())
	permissions, err := runtime.RBAC(nil)
	require.NoError(t, err)
	// Use a durable table: projection writes must share the exact SQL transaction.
	_, err = db.ExecContext(t.Context(), "CREATE TABLE IF NOT EXISTS goauth_host_transaction_probe (subject_id uuid PRIMARY KEY)")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE goauth_host_transaction_probe") })
	transaction := runtime.InAuthTransaction
	if owned {
		transaction = runtime.InOwnedAuthTransaction
	}
	rollback := errors.New("host projection rejected")
	for _, abort := range []bool{true, false} {
		var subject goauth.SubjectID
		err = transaction(t.Context(), func(ctx context.Context) error {
			account, err := runtime.ProvisionTrustedLocalAccount(ctx, goauth.RegisterRequest{Email: "delivery-disabled@example.test", Password: "Integration-Unique-Passphrase-1"})
			if err != nil {
				return err
			}
			subject = account.Subject.ID
			if _, err = runtime.UpdateBasicProfile(ctx, subject, goauth.BasicProfile{DisplayName: "Operator"}); err != nil {
				return err
			}
			if _, err = runtime.LogoutAll(ctx, subject); err != nil {
				return err
			}
			role, err := permissions.CreateRole(ctx, rbac.Role{Slug: "operator", Name: "Operator"}, nil)
			if err != nil {
				return err
			}
			if err = permissions.ReplaceSubjectRoles(ctx, subject, []int64{role.ID}); err != nil {
				return err
			}
			executor, err := runtime.SQLExecutor(ctx)
			if err != nil {
				return err
			}
			if _, err = executor.ExecContext(ctx, "INSERT INTO goauth_host_transaction_probe(subject_id) VALUES ($1)", subject); err != nil {
				return err
			}
			roles, err := permissions.SubjectRoles(ctx, subject)
			require.NoError(t, err)
			require.Len(t, roles, 1)
			if abort {
				return rollback
			}
			return nil
		})
		var subjects, projections, audit int
		require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_subjects WHERE id=$1", subject).Scan(&subjects))
		require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM goauth_host_transaction_probe WHERE subject_id=$1", subject).Scan(&projections))
		require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1", subject).Scan(&audit))
		if abort {
			require.ErrorIs(t, err, rollback)
			require.Zero(t, subjects)
			require.Zero(t, projections)
			require.Zero(t, audit)
		} else {
			require.NoError(t, err)
			require.Equal(t, 1, subjects)
			require.Equal(t, 1, projections)
			require.Positive(t, audit)
		}
	}
	var queued int
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_notification_deliveries").Scan(&queued))
	require.Zero(t, queued)
	account, err := runtime.FindAccount(t.Context(), goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "delivery-disabled@example.test"})
	require.NoError(t, err)
	_, err = runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{SubjectID: account.Subject.ID, CurrentPassword: "Integration-Unique-Passphrase-1", NewPassword: "Integration-New-Passphrase-2"})
	require.NoError(t, err)
	_, err = runtime.Login(t.Context(), goauth.LoginRequest{Realm: goauth.RealmUser, Credential: goauth.Credential{Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "delivery-disabled@example.test"}, Password: "Integration-New-Passphrase-2"}})
	require.NoError(t, err)
	require.ErrorIs(t, runtime.RequestPasswordReset(t.Context(), "delivery-disabled@example.test"), goauth.ErrNotificationDeliveryDisabled)
}
