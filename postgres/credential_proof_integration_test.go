//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestPreparedCredentialRevalidatesCanonicalSecurityAndHoldsSubjectLock(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	email := "prepared-credential@example.test"
	password := "Integration-Prepared-Passphrase-1"
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{Email: email, Password: password})
	require.NoError(t, err)
	credential := goauth.Credential{Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: email}, Password: password}
	proof, err := runtime.PrepareCredential(t.Context(), credential)
	require.NoError(t, err)
	_, err = runtime.RevalidateCredential(t.Context(), proof)
	require.ErrorContains(t, err, "requires managed auth transaction")
	changed := make(chan error, 1)
	require.NoError(t, runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		verified, err := runtime.RevalidateCredential(ctx, proof)
		if err != nil {
			return err
		}
		require.Equal(t, account.Subject.ID, verified.Subject.ID)
		go func() { _, err := runtime.LogoutAll(t.Context(), account.Subject.ID); changed <- err }()
		select {
		case err := <-changed:
			t.Fatalf("security mutation crossed held subject lock: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		return nil
	}))
	require.NoError(t, <-changed)
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error { _, err := runtime.RevalidateCredential(ctx, proof); return err })
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	fresh, err := runtime.PrepareCredential(t.Context(), credential)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "UPDATE auth_identifiers SET normalized_value=$2 WHERE subject_id=$1 AND is_primary", account.Subject.ID, "changed@example.test")
	require.NoError(t, err)
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error { _, err := runtime.RevalidateCredential(ctx, fresh); return err })
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	_, err = db.ExecContext(t.Context(), "UPDATE auth_identifiers SET normalized_value=$2 WHERE subject_id=$1 AND is_primary", account.Subject.ID, email)
	require.NoError(t, err)
	_, err = runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
	require.NoError(t, err)
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error { _, err := runtime.RevalidateCredential(ctx, fresh); return err })
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
}
