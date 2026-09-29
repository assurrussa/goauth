//go:build integration

package postgres_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestPostgresEmailChangeReauthenticationSharesDurableAdmission(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
	first, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	second, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	const password = "Postgres-Reauth-Initial-Passphrase-42"
	account, err := first.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "postgres.reauth@example.test", Password: password,
	})
	require.NoError(t, err)
	_, err = first.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: "wrong", NewPassword: "Postgres-Reauth-Replacement-Passphrase-42",
	})
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	err = second.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: password, NewEmail: "postgres.reauth.next@example.test",
	})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	var pending, deliveries int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_email_change_records`).Scan(&pending))
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_notification_deliveries`).Scan(&deliveries))
	require.Zero(t, pending)
	require.Zero(t, deliveries)
}

type postgresReauthHasher struct {
	goauth.PasswordHasher
	afterVerify func()
}

func (h *postgresReauthHasher) VerifyPassword(phc, password string) error {
	if err := h.PasswordHasher.VerifyPassword(phc, password); err != nil {
		return err
	}
	if h.afterVerify != nil {
		afterVerify := h.afterVerify
		h.afterVerify = nil
		afterVerify()
	}
	return nil
}

func TestPostgresEmailChangeRejectsSecurityMutationAfterPasswordVerification(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	control, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	const password = "Postgres-Reauth-Snapshot-Passphrase-42"
	account, err := control.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "postgres.reauth.snapshot@example.test", Password: password,
	})
	require.NoError(t, err)
	delegate, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	hasher := &postgresReauthHasher{PasswordHasher: delegate}
	config.PasswordHasher = hasher
	auth, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	hasher.afterVerify = func() {
		_, err := control.LogoutAll(t.Context(), account.Subject.ID)
		require.NoError(t, err)
	}
	err = auth.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: password, NewEmail: "postgres.reauth.next@example.test",
	})
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	_, err = auth.PendingEmailChange(t.Context(), account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	current, err := control.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, account.PrimaryEmail.NormalizedValue, current.PrimaryEmail.NormalizedValue)
	require.Equal(t, account.Subject.SecurityVersion+1, current.Subject.SecurityVersion)
}
