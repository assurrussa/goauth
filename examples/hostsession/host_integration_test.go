//go:build integration

package main

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestHostSessionPostgres(t *testing.T) {
	dsn := os.Getenv("GOAUTH_HOSTSESSION_TEST_DSN")
	require.NotEmpty(t, dsn, "set GOAUTH_HOSTSESSION_TEST_DSN to a disposable PostgreSQL database")
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	runtime, err := newRuntime(db)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Close()) })
	require.Same(t, db, runtime.Database())
	_, err = db.ExecContext(t.Context(), hostSchema)
	require.NoError(t, err)
	host := sessionHost{auth: runtime}
	const project = "test-project"
	const password = "Synthetic-Host-Password-42"
	seed := func(t *testing.T, member bool) (goauth.Account, goauth.Credential) {
		t.Helper()
		identifier := goauth.IdentifierInput{Scheme: loginScheme, Value: "test-" + goauth.NewSubjectID().String()}
		account, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{Identifier: identifier, Password: password})
		require.NoError(t, err)
		if member {
			_, err := db.ExecContext(t.Context(), `INSERT INTO example_host_memberships (subject_id, project_id) VALUES ($1, $2)`, account.Subject.ID, project)
			require.NoError(t, err)
		}
		return account, goauth.Credential{Identifier: identifier, Password: password}
	}
	assertNoSession := func(t *testing.T, subject goauth.SubjectID) {
		t.Helper()
		var count int
		require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM example_host_sessions WHERE subject_id=$1`, subject).Scan(&count))
		require.Zero(t, count)
	}

	t.Run("success and caller-owned pool", func(t *testing.T) {
		account, credential := seed(t, true)
		require.Zero(t, account.PrimaryEmail)
		require.False(t, account.EmailVerified())
		token, err := host.login(t.Context(), credential, project)
		require.NoError(t, err)
		require.True(t, token != "", "successful commit must return a bearer secret")
		got, err := host.authenticate(t.Context(), token, project)
		require.NoError(t, err)
		require.Equal(t, account.Subject.ID, got.Subject.ID)
		_, err = host.authenticate(t.Context(), token, "different-project")
		require.ErrorIs(t, err, errDenied)
		var digestLength int
		require.NoError(t, db.QueryRowContext(t.Context(), `SELECT octet_length(token_digest) FROM example_host_sessions WHERE subject_id=$1`, account.Subject.ID).Scan(&digestLength))
		require.Equal(t, 32, digestLength)
		require.NoError(t, demonstrate(t.Context(), db))
		require.NoError(t, db.PingContext(t.Context()), "closing Runtime must not close the host pool")
	})
	t.Run("wrong password", func(t *testing.T) {
		account, credential := seed(t, true)
		credential.Password = "Incorrect-Synthetic-Password"
		token, err := host.login(t.Context(), credential, project)
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
		require.True(t, token == "", "failure must withhold the bearer secret")
		assertNoSession(t, account.Subject.ID)
	})
	t.Run("missing membership", func(t *testing.T) {
		account, credential := seed(t, false)
		token, err := host.login(t.Context(), credential, project)
		require.ErrorIs(t, err, errDenied)
		require.True(t, token == "", "failure must withhold the bearer secret")
		assertNoSession(t, account.Subject.ID)
	})
	t.Run("disabled subject", func(t *testing.T) {
		account, credential := seed(t, true)
		proof, err := runtime.PrepareCredential(t.Context(), credential)
		require.NoError(t, err)
		_, err = runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
		require.NoError(t, err)
		token, err := host.finishLogin(t.Context(), proof, project)
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
		require.True(t, token == "", "failure must withhold the bearer secret")
		token, err = host.login(t.Context(), credential, project)
		require.Error(t, err)
		require.True(t, token == "", "failure must withhold the bearer secret")
		assertNoSession(t, account.Subject.ID)
	})
	t.Run("stale security version", func(t *testing.T) {
		account, credential := seed(t, true)
		proof, err := runtime.PrepareCredential(t.Context(), credential)
		require.NoError(t, err)
		_, err = runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
			SubjectID: account.Subject.ID, NewPassword: "New-Synthetic-Host-Password-42",
		})
		require.NoError(t, err)
		token, err := host.finishLogin(t.Context(), proof, project)
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
		require.True(t, token == "", "failure must withhold the bearer secret")
		assertNoSession(t, account.Subject.ID)
	})
	t.Run("reject ambient transaction", func(t *testing.T) {
		account, credential := seed(t, true)
		proof, err := runtime.PrepareCredential(t.Context(), credential)
		require.NoError(t, err)
		err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			token, err := host.finishLogin(ctx, proof, project)
			require.True(t, token == "", "failure must withhold the bearer secret")
			return err
		})
		require.ErrorIs(t, err, postgres.ErrAuthTransactionAlreadyActive)
		assertNoSession(t, account.Subject.ID)
	})
	for _, mutation := range []string{"disabled", "version", "membership", "expiry"} {
		t.Run("session rejects "+mutation, func(t *testing.T) {
			account, credential := seed(t, true)
			token, err := host.login(t.Context(), credential, project)
			require.NoError(t, err)
			switch mutation {
			case "disabled":
				_, err = runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
			case "version":
				_, err = runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
					SubjectID: account.Subject.ID, NewPassword: "Changed-Synthetic-Host-Password-42",
				})
			case "membership":
				_, err = db.ExecContext(t.Context(), `UPDATE example_host_memberships SET active=false WHERE subject_id=$1`, account.Subject.ID)
			case "expiry":
				_, err = db.ExecContext(t.Context(), `UPDATE example_host_sessions SET expires_at=$1 WHERE subject_id=$2`, time.Now().Add(-time.Second), account.Subject.ID)
			}
			require.NoError(t, err)
			got, err := host.authenticate(t.Context(), token, project)
			require.ErrorIs(t, err, errDenied)
			require.Zero(t, got)
		})
	}
}
