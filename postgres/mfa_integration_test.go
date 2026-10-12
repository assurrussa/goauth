//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

const mfaIntegrationPassword = "Integration-MFA-Passphrase-1"

type mfaIntegrationFixture struct {
	runtime *postgres.Runtime
	db      *sql.DB
	config  goauth.Config
	now     time.Time
	request goauth.LoginRequest
	auth    goauth.AuthContext
	account goauth.Account
}

// newMFASchemaIntegrationFixture verifies an empty schema without provisioning or login.
func newMFASchemaIntegrationFixture(t *testing.T) *mfaIntegrationFixture {
	t.Helper()
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	keys, err := goauth.NewKeyRing("mfa-1", goauth.Key{ID: "mfa-1", Material: bytes.Repeat([]byte{91}, 32)})
	require.NoError(t, err)
	config.MFAKeys = &keys
	f := &mfaIntegrationFixture{db: db, now: time.Now().UTC().Truncate(time.Second)}
	config.Now = func() time.Time { return f.now }
	config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Hour, Limit: 100}
	f.config = config
	f.runtime, err = postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	return f
}

func newMFAIntegrationFixture(t *testing.T) *mfaIntegrationFixture {
	t.Helper()
	f := newMFASchemaIntegrationFixture(t)
	var err error
	f.account, err = f.runtime.ProvisionTrustedLocalAccount(context.Background(),
		goauth.RegisterRequest{Email: "mfa-owner@example.test", Password: mfaIntegrationPassword})
	require.NoError(t, err)
	f.request = goauth.LoginRequest{
		Realm: goauth.RealmUser,
		Credential: goauth.Credential{Identifier: goauth.IdentifierInput{
			Scheme: goauth.IdentifierSchemeEmail,
			Value:  "mfa-owner@example.test",
		}, Password: mfaIntegrationPassword},
	}
	login, err := f.runtime.Login(context.Background(), f.request)
	require.NoError(t, err)
	f.auth, err = f.runtime.AuthenticateSession(context.Background(), login.Tokens.AccessToken)
	require.NoError(t, err)
	return f
}

func (f *mfaIntegrationFixture) enroll(t *testing.T) (goauth.MFAEnrollment, []string) {
	t.Helper()
	ctx := context.Background()
	binding := [32]byte{7}
	e, err := f.runtime.BeginMFAEnrollment(ctx, goauth.MFAEnrollmentRequest{
		Auth:     f.auth,
		Password: mfaIntegrationPassword, Binding: binding,
	})
	require.NoError(t, err)
	code, err := totp.GenerateCode(e.Secret, f.now)
	require.NoError(t, err)
	codes, err := f.runtime.ConfirmMFAEnrollment(ctx, goauth.MFAEnrollmentConfirmRequest{
		Auth:     f.auth,
		Password: mfaIntegrationPassword, EnrollmentID: e.ID, Code: code, Binding: binding,
	})
	require.NoError(t, err)
	require.Len(t, codes, 10)
	return e, codes
}

func TestLocalMFAEnrollmentLoginRefreshAndSingleUse(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	e, codes := f.enroll(t)
	ctx := context.Background()
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM auth_sessions WHERE revoked_at IS NOT NULL").Scan(&count))
	require.Equal(t, 1, count)
	legacy, err := f.runtime.Login(ctx, f.request)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	require.Empty(t, legacy.Tokens)
	binding := [32]byte{3}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	require.NotNil(t, begin.Pending)
	require.Empty(t, begin.Login)
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_sessions").Scan(&count))
	require.Equal(t, 1, count)
	code, err := totp.GenerateCode(e.Secret, f.now)
	require.NoError(t, err)
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, code)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	wrong := binding
	wrong[0] ^= 1
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, wrong, codes[0])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	login, err := f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.NoError(t, err)
	require.NotEmpty(t, login.Tokens.AccessToken)
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[1])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	_, err = f.runtime.Refresh(ctx, login.Tokens.RefreshToken)
	require.NoError(t, err)
	begin, err = f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
}

func TestLocalMFAMissingKeysAndWrongAttemptBudgetSurviveRuntimeRestart(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx := context.Background()
	binding := [32]byte{4}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	for range 3 {
		_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, "bad")
		require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	}
	var attempts int
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT attempts FROM auth_mfa_budget WHERE subject_id=$1",
		f.account.Subject.ID).Scan(&attempts))
	require.Equal(t, 5, attempts)
	restarted, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: f.config})
	require.NoError(t, err)
	for range 5 {
		_, err = restarted.CompleteLocalLogin(ctx, begin.Pending.ID, binding, "bad")
		require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	}
	_, err = restarted.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	config := f.config
	config.MFAKeys = nil
	unconfigured, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	_, err = unconfigured.Login(ctx, f.request)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	result, err := unconfigured.BeginLocalLogin(ctx, f.request, binding)
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.Empty(t, result)
	_, err = unconfigured.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
}

func TestLocalMFAConcurrentCompletionIssuesOneSession(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx := context.Background()
	binding := [32]byte{9}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else {
			require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
		}
	}
	require.Equal(t, 1, success)
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL").Scan(&count))
	require.Equal(t, 1, count)
}

func TestLocalMFAExpiredVersionChangedAndAmbientContinuationsDeny(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx := context.Background()
	binding := [32]byte{2}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	f.now = begin.Pending.ExpiresAt
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	begin, err = f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	_, err = f.runtime.LogoutAll(ctx, f.account.Subject.ID)
	require.NoError(t, err)
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	begin, err = f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	store, err := postgres.NewStore(f.db)
	require.NoError(t, err)
	err = store.InAuthTransaction(ctx, func(txctx context.Context) error {
		result, err := f.runtime.CompleteLocalLogin(txctx, begin.Pending.ID, binding, codes[0])
		require.Empty(t, result)
		return err
	})
	require.ErrorIs(t, err, postgres.ErrAuthTransactionAlreadyActive)
}

func TestLocalMFAUnenrolledAccountWorksWithoutKeys(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	enabled, err := f.runtime.MFAStatus(t.Context(), f.auth)
	require.NoError(t, err)
	require.False(t, enabled)
	config := f.config
	config.MFAKeys = nil
	runtime, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	ctx := context.Background()
	enabled, err = runtime.MFAStatus(ctx, f.auth)
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.False(t, enabled)
	begin, err := runtime.BeginLocalLogin(ctx, f.request, [32]byte{})
	require.NoError(t, err)
	require.Nil(t, begin.Pending)
	require.NotEmpty(t, begin.Login.Tokens.AccessToken)
	_, err = runtime.BeginMFAEnrollment(ctx, goauth.MFAEnrollmentRequest{
		Auth:     f.auth,
		Password: mfaIntegrationPassword, Binding: [32]byte{1},
	})
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
}

func TestLocalMFAStatusPreservesEnrollmentWithoutKeys(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx := t.Context()
	binding := [32]byte{17}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	login, err := f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.NoError(t, err)
	auth, err := f.runtime.AuthenticateSession(ctx, login.Tokens.AccessToken)
	require.NoError(t, err)
	enabled, err := f.runtime.MFAStatus(ctx, auth)
	require.NoError(t, err)
	require.True(t, enabled)
	config := f.config
	config.MFAKeys = nil
	runtime, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	enabled, err = runtime.MFAStatus(ctx, auth)
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.True(t, enabled)
}

func TestLocalMFAManagementRequiresSessionPasswordAndFactor(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx := context.Background()
	binding := [32]byte{5}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	login, err := f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.NoError(t, err)
	auth, err := f.runtime.AuthenticateSession(ctx, login.Tokens.AccessToken)
	require.NoError(t, err)
	err = f.runtime.DisableMFA(ctx, goauth.MFAChangeRequest{Auth: auth, Password: "wrong", Code: codes[1]})
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	err = f.runtime.DisableMFA(ctx, goauth.MFAChangeRequest{Auth: auth, Password: mfaIntegrationPassword, Code: "bad"})
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	regenerated, err := f.runtime.RegenerateMFARecovery(ctx, goauth.MFAChangeRequest{
		Auth:     auth,
		Password: mfaIntegrationPassword, Code: codes[1],
	})
	require.NoError(t, err)
	require.Len(t, regenerated, 10)
	_, err = f.runtime.AuthenticateSession(ctx, login.Tokens.AccessToken)
	require.Error(t, err)
	begin, err = f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[2])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	login, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, regenerated[0])
	require.NoError(t, err)
	auth, err = f.runtime.AuthenticateSession(ctx, login.Tokens.AccessToken)
	require.NoError(t, err)
	err = f.runtime.DisableMFA(ctx, goauth.MFAChangeRequest{Auth: auth, Password: mfaIntegrationPassword, Code: regenerated[1]})
	require.NoError(t, err)
	_, err = f.runtime.Login(ctx, f.request)
	require.NoError(t, err)
}

func TestLocalMFALoginRollsBackFactorAndChallengeWhenAuditFails(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx := context.Background()
	binding := [32]byte{8}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(),
		"ALTER TABLE auth_security_audit_events ADD CONSTRAINT reject_mfa_login CHECK (event_type <> 'mfa.login')")
	require.NoError(t, err)
	result, err := f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.Error(t, err)
	require.Empty(t, result)
	_, err = f.db.ExecContext(t.Context(), "ALTER TABLE auth_security_audit_events DROP CONSTRAINT reject_mfa_login")
	require.NoError(t, err)
	_, err = f.runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.NoError(t, err)
}

func TestLocalMFAMigrationPreservesExistingState(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	removeLocalMFASchema(t, f.db)
	require.ErrorIs(t, postgres.VerifySchema(context.Background(), f.db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(context.Background(), f.db))
	require.NoError(t, postgres.Migrate(context.Background(), f.db))
	account, err := f.runtime.GetAccount(context.Background(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, f.account.Subject.SecurityVersion, account.Subject.SecurityVersion)
	expected, actual := f.account.PrimaryEmail, account.PrimaryEmail
	require.True(t, expected.CreatedAt.Equal(actual.CreatedAt))
	require.True(t, expected.UpdatedAt.Equal(actual.UpdatedAt))
	require.NotNil(t, expected.VerifiedAt)
	require.NotNil(t, actual.VerifiedAt)
	require.True(t, expected.VerifiedAt.Equal(*actual.VerifiedAt))
	// Compare every remaining identifier field after normalizing only the
	// already-asserted timestamp representation returned by PostgreSQL.
	actual.CreatedAt, actual.UpdatedAt, actual.VerifiedAt = expected.CreatedAt, expected.UpdatedAt, expected.VerifiedAt
	require.Equal(t, expected, actual)
}

func removeLocalMFASchema(t *testing.T, db *sql.DB) {
	t.Helper()
	removeRequiredMFASchema(t, db)
	_, err := db.ExecContext(t.Context(), `DROP TABLE auth_mfa_enrollments,auth_mfa_pending,
		auth_mfa_budget,auth_mfa_recovery,auth_mfa_factors;
		DELETE FROM goauth_migration_history WHERE version=9;
		DELETE FROM goauth_schema_version WHERE version=9`)
	require.NoError(t, err)
}
