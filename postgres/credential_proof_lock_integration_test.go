//go:build integration

//nolint:testpackage // Shortens private proof expiry to exercise a real database lock wait without a five-minute test.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestPreparedCredentialExpiresDuringRealSubjectLockWait(t *testing.T) {
	dsn := os.Getenv("GOAUTH_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_TEST_POSTGRES_DSN is not configured")
	}
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	require.NoError(t, Migrate(t.Context(), db))
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	runtime, err := NewRuntime(Config{DB: db, Runtime: goauth.Config{
		NotificationDelivery: goauth.NotificationDeliveryDisabled,
		Signing:              goauth.SigningConfig{Issuer: "https://auth.example.test", Audience: "expiry", Keys: fixture.SigningKeys},
		TokenHMACKeys:        fixture.TokenKeys,
	}})
	require.NoError(t, err)
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: fmt.Sprintf("proof-expiry-%d@example.test", time.Now().UnixNano()), Password: "Integration-Expiry-Passphrase-1",
	})
	require.NoError(t, err)
	proof, err := runtime.PrepareCredential(t.Context(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: account.PrimaryEmail.DisplayValue},
		Password:   "Integration-Expiry-Passphrase-1",
	})
	require.NoError(t, err)
	holder, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback() }()
	var id goauth.SubjectID
	require.NoError(t, holder.QueryRowContext(t.Context(), "SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE",
		account.Subject.ID).Scan(&id))
	proof.expiresAt = time.Now().Add(time.Second)
	backend := make(chan int, 1)
	result := make(chan error, 1)
	go func() {
		result <- runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			executor, err := runtime.SQLExecutor(ctx)
			if err != nil {
				return err
			}
			var pid int
			if err = executor.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
				return err
			}
			backend <- pid
			_, err = runtime.RevalidateCredential(ctx, proof)
			return err
		})
	}()
	pid := <-backend
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRowContext(t.Context(), "SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=$1", pid).Scan(&waiting)
		return err == nil && waiting
	}, time.Second, 10*time.Millisecond, "revalidation must enter the real row-lock wait while proof is valid")
	<-time.After(time.Until(proof.expiresAt) + 20*time.Millisecond)
	require.NoError(t, holder.Commit())
	require.ErrorIs(t, <-result, goauth.ErrInvalidCredentials, "lock wait must not extend the proof validity window")
}
