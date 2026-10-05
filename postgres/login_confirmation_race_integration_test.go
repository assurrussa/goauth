//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

type postgresConfirmationLoginResult struct {
	login goauth.LoginResult
	err   error
}

func TestPostgresLoginConfirmationSerializesAfterVerification(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	var armed atomic.Bool
	var preparations atomic.Int64
	prepared := make(chan struct{}, 1)
	config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
		_ context.Context, _ goauth.Realm, account goauth.Account, claims map[string]any,
	) error {
		claims["email_verified"] = account.EmailVerified()
		if armed.Load() && preparations.Add(1) == 1 {
			prepared <- struct{}{}
		}
		return nil
	})
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	const email = "pg.login.confirmation.race@example.test"
	registered := register(t, runtime, email)
	code := postgresLoginChallenge(t, db, runtime, registered.Account.Subject.ID)
	result := make(chan postgresConfirmationLoginResult, 1)
	armed.Store(true)
	// Verification owns the real subject row lock while Login reads and signs
	// the old unverified account. Confirm only after Login waits on that lock.
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		executor, executorErr := runtime.SQLExecutor(ctx)
		if executorErr != nil {
			return executorErr
		}
		var subjectID goauth.SubjectID
		var holderPID int
		if lockErr := executor.QueryRowContext(ctx,
			`SELECT id, pg_backend_pid() FROM auth_subjects WHERE id=$1 FOR UPDATE`,
			registered.Account.Subject.ID).Scan(&subjectID, &holderPID); lockErr != nil {
			return lockErr
		}
		go func() {
			loggedIn, loginErr := runtime.Login(t.Context(), login(email, sessionPreparationPassword))
			result <- postgresConfirmationLoginResult{login: loggedIn, err: loginErr}
		}()
		select {
		case <-prepared:
		case <-time.After(5 * time.Second):
			t.Fatal("Login did not prepare its initial unverified snapshot")
		}
		require.Eventually(t, func() bool {
			var blocked bool
			queryErr := db.QueryRowContext(t.Context(), `SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
)`, holderPID).Scan(&blocked)
			return queryErr == nil && blocked
		}, 5*time.Second, 10*time.Millisecond, "Login must wait on verification's canonical subject lock")
		_, verifyErr := runtime.VerifyEmailChallenge(ctx, subjectID, goauth.EmailChallengePurposeVerification, code)
		return verifyErr
	})
	require.NoError(t, err)
	var outcome postgresConfirmationLoginResult
	select {
	case outcome = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("Login did not complete after verification committed")
	}
	armed.Store(false)
	require.NoError(t, outcome.err)
	require.EqualValues(t, 2, preparations.Load(), "exactly one verified re-preparation is allowed")
	require.True(t, outcome.login.Account.EmailVerified())
	require.Equal(t, registered.Account.Subject.SecurityVersion, outcome.login.Account.Subject.SecurityVersion)
	assertPostgresLoginScope(t, db, runtime, outcome.login.Tokens, goauth.SessionScopeAuthenticated)
	auth, err := runtime.VerifyJWT(t.Context(), outcome.login.Tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, true, auth.Claims["email_verified"])
	assertPostgresLoginRows(t, db, 2)
	assertPostgresConfirmedLoginRefresh(t, db, runtime, outcome.login.Tokens, code)
}

func TestPostgresLoginConfirmationSerializesBeforeVerification(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	const email = "pg.login.before.confirmation@example.test"
	registered := register(t, runtime, email)
	code := postgresLoginChallenge(t, db, runtime, registered.Account.Subject.ID)
	holder, holderPID := blockPostgresLoginInsertion(t, db)
	defer func() { _ = holder.Rollback() }()
	loginResult := make(chan postgresConfirmationLoginResult, 1)
	go func() {
		loggedIn, loginErr := runtime.Login(t.Context(), login(email, sessionPreparationPassword))
		loginResult <- postgresConfirmationLoginResult{login: loggedIn, err: loginErr}
	}()
	// The test-only trigger stops Login after it has locked the canonical subject
	// and inserted the session, before commit. Verification must wait behind it.
	var loginPID int
	require.Eventually(t, func() bool {
		queryErr := db.QueryRowContext(t.Context(),
			`SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`, holderPID).Scan(&loginPID)
		return queryErr == nil
	}, 5*time.Second, 10*time.Millisecond, "Login must hold its subject lock while inserting the session")
	verified := make(chan error, 1)
	go func() {
		_, verifyErr := runtime.VerifyEmailChallenge(t.Context(), registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification, code)
		verified <- verifyErr
	}()
	require.Eventually(t, func() bool {
		var blocked bool
		queryErr := db.QueryRowContext(t.Context(), `SELECT EXISTS (
    SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
)`, loginPID).Scan(&blocked)
		return queryErr == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "verification must wait on Login's canonical subject lock")
	require.NoError(t, holder.Commit())
	var outcome postgresConfirmationLoginResult
	select {
	case outcome = <-loginResult:
	case <-time.After(5 * time.Second):
		t.Fatal("Login did not commit after insertion resumed")
	}
	select {
	case err := <-verified:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("verification did not finish after Login committed")
	}
	require.NoError(t, outcome.err)
	require.Equal(t, goauth.SessionScopeConfirmation, outcome.login.Tokens.Session.Scope)
	claims, err := runtime.VerifyJWT(t.Context(), outcome.login.Tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeConfirmation, claims.Scope)
	_, err = runtime.AuthenticateSession(t.Context(), outcome.login.Tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrInvalidToken, "confirmation JWT stays restricted after the session is promoted")
	assertPostgresLoginRows(t, db, 2)
	assertPostgresConfirmedLoginRefresh(t, db, runtime, outcome.login.Tokens, code)
}

func blockPostgresLoginInsertion(t *testing.T, db *sql.DB) (*sql.Tx, int) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
CREATE FUNCTION goauth_test_pause_login_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(791273);
    RETURN NEW;
END;
$$;
CREATE TRIGGER goauth_test_pause_login AFTER INSERT ON auth_sessions
FOR EACH ROW EXECUTE FUNCTION goauth_test_pause_login_insert();`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := db.ExecContext(context.Background(), `
DROP TRIGGER IF EXISTS goauth_test_pause_login ON auth_sessions;
DROP FUNCTION IF EXISTS goauth_test_pause_login_insert();`)
		require.NoError(t, cleanupErr)
	})
	holder, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	_, err = holder.ExecContext(t.Context(), `SELECT pg_advisory_xact_lock(791273)`)
	require.NoError(t, err)
	var pid int
	require.NoError(t, holder.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid))
	return holder, pid
}

func TestPostgresLoginConfirmationRetryPreservesRevocationFence(t *testing.T) {
	db := integrationDB(t)
	for _, suspend := range []bool{false, true} {
		name := "logout all"
		if suspend {
			name = "suspension"
		}
		t.Run(name, func(t *testing.T) {
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			config := runtimeConfig(t)
			var runtime *postgres.Runtime
			var code string
			var armed bool
			var preparations int
			config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
				ctx context.Context, _ goauth.Realm, account goauth.Account, _ map[string]any,
			) error {
				if !armed {
					return nil
				}
				preparations++
				if preparations == 1 {
					_, verifyErr := runtime.VerifyEmailChallenge(ctx, account.Subject.ID,
						goauth.EmailChallengePurposeVerification, code)
					return verifyErr
				}
				if suspend {
					_, statusErr := runtime.SetSubjectStatus(ctx, account.Subject.ID, goauth.SubjectStatusSuspended)
					return statusErr
				}
				_, logoutErr := runtime.LogoutAll(ctx, account.Subject.ID)
				return logoutErr
			})
			var err error
			runtime, err = postgres.NewRuntime(postgres.Config{
				DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
			})
			require.NoError(t, err)
			const email = "pg.login.confirmation.revoked@example.test"
			registered := register(t, runtime, email)
			code = postgresLoginChallenge(t, db, runtime, registered.Account.Subject.ID)
			armed = true
			result, err := runtime.Login(t.Context(), login(email, sessionPreparationPassword))
			if suspend {
				require.ErrorIs(t, err, goauth.ErrAccountUnavailable)
			} else {
				require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
			}
			require.Zero(t, result)
			require.Equal(t, 2, preparations)
			assertPostgresLoginRows(t, db, 1)
			var active int
			require.NoError(t, db.QueryRowContext(t.Context(),
				`SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL`).Scan(&active))
			require.Zero(t, active)
		})
	}
}

func TestPostgresCreateSessionRejectsStaleConfirmationScope(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "pg.login.direct.scope@example.test")
	code := postgresLoginChallenge(t, db, runtime, registered.Account.Subject.ID)
	_, err := runtime.VerifyEmailChallenge(t.Context(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification, code)
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	record := goauth.SessionRecord{Session: registered.Tokens.Session}
	record.Session.ID = uuid.NewString()
	record.FamilyID = uuid.NewString()
	record.RefreshSelector = "stale-confirmation-selector"
	record.RefreshDigest = goauth.SecretDigest{KeyID: "token-v1", Digest: make([]byte, 32)}
	record.RefreshExpiresAt = registered.Tokens.RefreshExpiresAt
	require.ErrorIs(t, store.CreateSession(t.Context(), record), goauth.ErrSecurityVersionMismatch)
	assertPostgresLoginRows(t, db, 1)
}

func postgresLoginChallenge(t *testing.T, db *sql.DB, runtime *postgres.Runtime, subjectID goauth.SubjectID) string {
	t.Helper()
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), subjectID, goauth.EmailChallengePurposeVerification))
	return integrationNotificationCode(t, runtime, &integrationEventObserver{t: t, db: db}, "email_challenge")
}

func assertPostgresLoginRows(t *testing.T, db *sql.DB, expected int) {
	t.Helper()
	var sessions, families, tokens int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT
    (SELECT count(*) FROM auth_sessions),
    (SELECT count(*) FROM auth_refresh_families),
    (SELECT count(*) FROM auth_refresh_tokens)`).Scan(&sessions, &families, &tokens))
	require.Equal(t, expected, sessions)
	require.Equal(t, expected, families)
	require.Equal(t, expected, tokens)
}

func assertPostgresLoginScope(
	t *testing.T, db *sql.DB, runtime *postgres.Runtime, tokens goauth.TokenPair, scope goauth.SessionScope,
) {
	t.Helper()
	auth, err := runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, scope, auth.Scope)
	require.Equal(t, scope, tokens.Session.Scope)
	var stored string
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT scope FROM auth_sessions WHERE id=$1`, tokens.Session.ID).Scan(&stored))
	require.Equal(t, string(scope), stored)
}

func assertPostgresConfirmedLoginRefresh(
	t *testing.T, db *sql.DB, runtime *postgres.Runtime, tokens goauth.TokenPair, code string,
) {
	t.Helper()
	rotated, err := runtime.Refresh(t.Context(), tokens.RefreshToken)
	require.NoError(t, err)
	assertPostgresLoginScope(t, db, runtime, rotated, goauth.SessionScopeAuthenticated)
	_, err = runtime.VerifyEmailChallenge(t.Context(), tokens.Session.SubjectID, goauth.EmailChallengePurposeVerification, code)
	require.NoError(t, err)
	again, err := runtime.Refresh(t.Context(), rotated.RefreshToken)
	require.NoError(t, err)
	assertPostgresLoginScope(t, db, runtime, again, goauth.SessionScopeAuthenticated)
}
