//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func requiredMFARuntime(t *testing.T, f *mfaIntegrationFixture) *postgres.Runtime {
	t.Helper()
	config := f.config
	config.MFAMode = goauth.MFAModeRequired
	runtime, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	require.Equal(t, goauth.MFAModeRequired, runtime.MFAMode())
	return runtime
}

func requiredMFASetup(
	t *testing.T, f *mfaIntegrationFixture, runtime *postgres.Runtime, binding [32]byte,
) (*goauth.MFALoginChallenge, goauth.MFAEnrollment) {
	t.Helper()
	result, err := runtime.BeginLocalLogin(t.Context(), f.request, binding)
	require.NoError(t, err)
	require.Empty(t, result.Login)
	require.NotNil(t, result.Pending)
	require.Equal(t, goauth.MFALoginKindEnrollment, result.Pending.Kind)
	setup, err := runtime.BeginLocalLoginEnrollment(t.Context(), result.Pending.ID, binding)
	require.NoError(t, err)
	require.Len(t, setup.RecoveryCodes, 10)
	require.True(t, result.Pending.ExpiresAt.Equal(setup.ExpiresAt))
	return result.Pending, setup
}

func TestRequiredMFAEnrollmentCreatesNoAuthorityBeforeConfirmation(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	runtime := requiredMFARuntime(t, f)
	ctx := t.Context()
	legacy, err := runtime.Login(ctx, f.request)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	require.Empty(t, legacy)
	binding := [32]byte{21}
	pending, setup := requiredMFASetup(t, f, runtime, binding)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_sessions").Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_mfa_recovery").Scan(&count))
	require.Zero(t, count)
	result, err := runtime.CompleteLocalLogin(ctx, pending.ID, binding, setup.RecoveryCodes[0])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, result)
	wrong := binding
	wrong[0]++
	result, err = runtime.CompleteLocalLoginEnrollment(ctx, pending.ID, setup.ID, wrong, "000000")
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, result)
	result, err = runtime.CompleteLocalLoginEnrollment(ctx, pending.ID, setup.ID, binding, "bad")
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, result)
	code, err := totp.GenerateCode(setup.Secret, f.now)
	require.NoError(t, err)
	result, err = runtime.CompleteLocalLoginEnrollment(ctx, pending.ID, setup.ID, binding, code)
	require.NoError(t, err)
	require.NotEmpty(t, result.Tokens.AccessToken)
	require.Equal(t, f.account.Subject.SecurityVersion+1, result.Account.Subject.SecurityVersion)
	_, err = runtime.AuthenticateSession(ctx, result.Tokens.AccessToken)
	require.NoError(t, err)
	refreshed, err := runtime.Refresh(ctx, result.Tokens.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, result.Tokens.Session.ID, refreshed.Session.ID)
	var admission string
	require.NoError(t, f.db.QueryRowContext(ctx,
		"SELECT mfa_admission FROM auth_sessions WHERE id=$1", result.Tokens.Session.ID).Scan(&admission))
	require.Equal(t, "factor", admission)
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_mfa_recovery").Scan(&count))
	require.Equal(t, 10, count)
	result, err = runtime.CompleteLocalLoginEnrollment(ctx, pending.ID, setup.ID, binding, code)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, result)
	begin, err := runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	require.Equal(t, goauth.MFALoginKindFactor, begin.Pending.Kind)
	_, err = runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, setup.RecoveryCodes[0])
	require.NoError(t, err)
}

func TestRequiredMFAPolicySwitchBlocksLegacySessionAndRefresh(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	login, err := f.runtime.Login(t.Context(), f.request)
	require.NoError(t, err)
	runtime := requiredMFARuntime(t, f)
	_, err = runtime.AuthenticateSession(t.Context(), login.Tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	tokens, err := runtime.Refresh(t.Context(), login.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	require.Empty(t, tokens)
	// The rejected rotation rolls back, so optional policy still authenticates
	// the same unconsumed refresh token without a migration of old authority.
	_, err = f.runtime.Refresh(t.Context(), login.Tokens.RefreshToken)
	require.NoError(t, err)
}

func TestRequiredMFAExternalAdmissionDoesNotRequireLocalFactor(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	runtime := requiredMFARuntime(t, f)
	login, err := runtime.LoginExternal(t.Context(), goauth.ExternalLoginRequest{
		Realm: goauth.RealmUser,
		Identity: goauth.ExternalIdentity{
			Issuer: "https://trusted.example.test", Subject: "external-required",
			Email: "external-required@example.test", EmailVerified: true,
		},
	})
	require.NoError(t, err)
	var admission string
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT mfa_admission FROM auth_sessions WHERE id=$1", login.Tokens.Session.ID).Scan(&admission))
	require.Equal(t, "external", admission)
	_, err = runtime.AuthenticateSession(t.Context(), login.Tokens.AccessToken)
	require.NoError(t, err)
	_, err = runtime.Refresh(t.Context(), login.Tokens.RefreshToken)
	require.NoError(t, err)
}

func TestRequiredMFAReplacementPolicyExpiryAndVersionFences(t *testing.T) {
	for _, scenario := range []string{
		"replacement", "optional-policy", "expiry", "security-version", "factor-revision", "deleted-pending",
	} {
		t.Run(scenario, func(t *testing.T) {
			f := newMFAIntegrationFixture(t)
			runtime := requiredMFARuntime(t, f)
			binding := [32]byte{22}
			pending, setup := requiredMFASetup(t, f, runtime, binding)
			code, err := totp.GenerateCode(setup.Secret, f.now)
			require.NoError(t, err)
			switch scenario {
			case "replacement":
				replacement, err := runtime.BeginLocalLoginEnrollment(t.Context(), pending.ID, binding)
				require.NoError(t, err)
				require.NotEqual(t, setup.ID, replacement.ID)
			case "optional-policy":
				runtime = f.runtime
			case "expiry":
				f.now = pending.ExpiresAt
			case "security-version":
				_, err = runtime.LogoutAll(t.Context(), f.account.Subject.ID)
				require.NoError(t, err)
			case "factor-revision":
				_, err = f.db.ExecContext(t.Context(),
					"UPDATE auth_mfa_factors SET revision=revision+1 WHERE subject_id=$1", f.account.Subject.ID)
				require.NoError(t, err)
			case "deleted-pending":
				_, err = f.db.ExecContext(t.Context(), "DELETE FROM auth_mfa_pending WHERE id=$1", pending.ID)
				require.NoError(t, err)
			}
			result, err := runtime.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, binding, code)
			require.Error(t, err)
			require.Empty(t, result)
			var enabled bool
			require.NoError(t, f.db.QueryRowContext(t.Context(),
				"SELECT enabled FROM auth_mfa_factors WHERE subject_id=$1", f.account.Subject.ID).Scan(&enabled))
			require.False(t, enabled)
		})
	}
}

func TestRequiredMFAConcurrentConfirmationSingleWinner(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	runtime := requiredMFARuntime(t, f)
	binding := [32]byte{23}
	pending, setup := requiredMFASetup(t, f, runtime, binding)
	code, err := totp.GenerateCode(setup.Secret, f.now)
	require.NoError(t, err)
	results := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Go(func() {
			_, err := runtime.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, binding, code)
			results <- err
		})
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL").Scan(&count))
	require.Equal(t, 1, count)
}

func TestRequiredMFAUnknownCommitWithholdsNewSession(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	runtime := requiredMFARuntime(t, f)
	binding := [32]byte{24}
	pending, setup := requiredMFASetup(t, f, runtime, binding)
	code, err := totp.GenerateCode(setup.Secret, f.now)
	require.NoError(t, err)
	store, err := postgres.NewStore(f.db)
	require.NoError(t, err)
	transaction := &mfaLostAcknowledgment{Store: store}
	config := f.config
	config.MFAMode = goauth.MFAModeRequired
	config.Store = store
	config.AuthTransaction = transaction
	config.AuditSink = store
	core, err := goauth.NewRuntime(config)
	require.NoError(t, err)
	result, err := core.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, binding, code)
	require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Empty(t, result)
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM auth_sessions WHERE mfa_admission='factor' AND revoked_at IS NULL").Scan(&count))
	require.Equal(t, 1, count)
}

func TestRequiredMFAFinalAuditFailureRollsBackEnrollmentAndAdmission(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	runtime := requiredMFARuntime(t, f)
	binding := [32]byte{25}
	pending, setup := requiredMFASetup(t, f, runtime, binding)
	code, err := totp.GenerateCode(setup.Secret, f.now)
	require.NoError(t, err)
	store, err := postgres.NewStore(f.db)
	require.NoError(t, err)
	injected := errors.New("injected mandatory audit failure")
	config := f.config
	config.MFAMode = goauth.MFAModeRequired
	config.Store = store
	config.AuthTransaction = store
	config.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
		if event.Type == "mfa.login" {
			return injected
		}
		return store.RecordSecurityEvent(ctx, event)
	})
	core, err := goauth.NewRuntime(config)
	require.NoError(t, err)
	result, err := core.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, binding, code)
	require.ErrorIs(t, err, injected)
	require.Empty(t, result)
	var enabled bool
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT enabled FROM auth_mfa_factors WHERE subject_id=$1", f.account.Subject.ID).Scan(&enabled))
	require.False(t, enabled)
	var version int64
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT security_version FROM auth_subjects WHERE id=$1", f.account.Subject.ID).Scan(&version))
	require.Equal(t, f.account.Subject.SecurityVersion, version)
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM auth_sessions WHERE mfa_admission='factor'").Scan(&count))
	require.Zero(t, count)
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM auth_mfa_pending WHERE id=$1", pending.ID).Scan(&count))
	require.Equal(t, 1, count)
}

func TestRequiredMFAMigrationDefaultsAndConstraints(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	var admission string
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT mfa_admission FROM auth_sessions WHERE id=$1", f.auth.SessionID).Scan(&admission))
	require.Equal(t, "unknown", admission)
	_, err := f.db.ExecContext(t.Context(), "UPDATE auth_sessions SET mfa_admission='browser' WHERE id=$1", f.auth.SessionID)
	require.Error(t, err)
	runtime := requiredMFARuntime(t, f)
	pending, _ := requiredMFASetup(t, f, runtime, [32]byte{26})
	for _, assignment := range []string{"kind='other'", "kind='factor'", "setup_recovery='bad'::bytea", "setup_id=''"} {
		_, err = f.db.ExecContext(t.Context(), "UPDATE auth_mfa_pending SET "+assignment+" WHERE id=$1", pending.ID)
		require.Error(t, err)
	}
	require.NoError(t, postgres.VerifySchema(t.Context(), f.db))
}

func TestRequiredMFAVerifyRejectsWeakenedLiveSchema(t *testing.T) {
	tests := map[string]string{
		"admission default":        "ALTER TABLE auth_sessions ALTER COLUMN mfa_admission SET DEFAULT 'external'",
		"admission default absent": "ALTER TABLE auth_sessions ALTER COLUMN mfa_admission DROP DEFAULT",
		"same named admission check": "ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_mfa_admission_check; ALTER " +
			"TABLE auth_sessions ADD CONSTRAINT auth_sessions_mfa_admission_check CHECK (true)",
		"widened admission check": "ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_mfa_admission_check; ALTER " +
			"TABLE auth_sessions ADD CONSTRAINT auth_sessions_mfa_admission_check CHECK " +
			"(mfa_admission IN ('unknown','factor','external','client'))",
		"setup check": "ALTER TABLE auth_mfa_pending DROP CONSTRAINT auth_mfa_pending_setup_check; ALTER " +
			"TABLE auth_mfa_pending ADD CONSTRAINT auth_mfa_pending_setup_check CHECK (true)",
		"pending kind": "ALTER TABLE auth_mfa_pending DROP CONSTRAINT auth_mfa_pending_kind_check; ALTER " +
			"TABLE auth_mfa_pending ADD CONSTRAINT auth_mfa_pending_kind_check CHECK (true)",
		"factor enabled default": "ALTER TABLE auth_mfa_factors ALTER COLUMN enabled SET DEFAULT true",
		"attempt budget check": "ALTER TABLE auth_mfa_budget DROP CONSTRAINT auth_mfa_budget_attempts_check; ALTER " +
			"TABLE auth_mfa_budget ADD CONSTRAINT auth_mfa_budget_attempts_check CHECK (true)",
		"pending expiry": "ALTER TABLE auth_mfa_pending DROP CONSTRAINT auth_mfa_pending_check; ALTER TABLE " +
			"auth_mfa_pending ADD CONSTRAINT auth_mfa_pending_check CHECK (true)",
		"binding check": "ALTER TABLE auth_mfa_pending DROP CONSTRAINT auth_mfa_pending_binding_check; ALTER " +
			"TABLE auth_mfa_pending ADD CONSTRAINT auth_mfa_pending_binding_check CHECK (true)",
		"pending subject foreign key": "ALTER TABLE auth_mfa_pending DROP CONSTRAINT auth_mfa_pending_subject_id_fkey",
		"pending uniqueness":          "ALTER TABLE auth_mfa_pending DROP CONSTRAINT auth_mfa_pending_subject_id_realm_key",
		"expiry index":                "DROP INDEX auth_mfa_pending_expiry_idx",
	}
	for name, ddl := range tests {
		t.Run(name, func(t *testing.T) {
			f := newMFASchemaIntegrationFixture(t)
			_, err := f.db.ExecContext(t.Context(), ddl)
			require.NoError(t, err)
			require.Error(t, postgres.VerifySchema(t.Context(), f.db))
			_, err = postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: f.config})
			require.Error(t, err)
		})
	}
}

func TestRequiredMFAFinalLockWaitRechecksEnrollmentExpiry(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	runtime := requiredMFARuntime(t, f)
	binding := [32]byte{27}
	pending, setup := requiredMFASetup(t, f, runtime, binding)
	code, err := totp.GenerateCode(setup.Secret, f.now)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	var clock atomic.Int64
	clock.Store(f.now.UnixNano())
	prepared := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	config := f.config
	config.MFAMode = goauth.MFAModeRequired
	config.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
		ctx context.Context, _ goauth.Realm, _ goauth.Account, _ map[string]any,
	) error {
		close(prepared)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	guarded, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	type outcome struct {
		result goauth.LoginResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := guarded.CompleteLocalLoginEnrollment(ctx, pending.ID, setup.ID, binding, code)
		done <- outcome{result: result, err: err}
	}()
	select {
	case <-prepared:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	blocker, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { err := blocker.Rollback(); require.True(t, err == nil || errors.Is(err, sql.ErrTxDone)) }()
	var subject string
	require.NoError(t, blocker.QueryRowContext(ctx,
		"SELECT id::text FROM auth_subjects WHERE id=$1 FOR UPDATE", f.account.Subject.ID).Scan(&subject))
	close(release)
	require.Eventually(t, func() bool {
		var waiting bool
		err := f.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
   AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%auth_subjects%')`).Scan(&waiting)
		return err == nil && waiting
	}, 5*time.Second, 10*time.Millisecond)
	clock.Store(pending.ExpiresAt.UnixNano())
	require.NoError(t, blocker.Commit())
	select {
	case got := <-done:
		require.ErrorIs(t, got.err, goauth.ErrMFALoginDenied)
		require.Empty(t, got.result)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var enabled bool
	require.NoError(t, f.db.QueryRowContext(ctx,
		"SELECT enabled FROM auth_mfa_factors WHERE subject_id=$1", f.account.Subject.ID).Scan(&enabled))
	require.False(t, enabled)
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_sessions WHERE mfa_admission='factor'").Scan(&count))
	require.Zero(t, count)
}

func removeRequiredMFASchema(t *testing.T, db *sql.DB) {
	t.Helper()
	removeScopedEmailSchema(t, db)
	_, err := db.ExecContext(t.Context(), `ALTER TABLE auth_sessions DROP COLUMN mfa_admission;
 ALTER TABLE auth_mfa_pending DROP COLUMN kind, DROP COLUMN setup_id, DROP COLUMN setup_key_id,
 DROP COLUMN setup_secret, DROP COLUMN setup_recovery;
 DELETE FROM goauth_migration_history WHERE version=10;
 DELETE FROM goauth_schema_version WHERE version=10`)
	require.NoError(t, err)
}
