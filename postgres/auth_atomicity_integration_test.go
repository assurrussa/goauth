//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/testkit"
)

const (
	postgresAtomicityPassword = "Integration-Unique-Passphrase-1"
	postgresAtomicityStatus   = "status"
)

var errPostgresAtomicityHook = errors.New("injected transaction hook failure")

func TestPostgresAuthAtomicityClaimsFailurePreservesRegistrationAndRefresh(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	var fail atomic.Bool
	fail.Store(true)
	config := runtimeConfig(t)
	config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(context.Context, goauth.Realm, goauth.Account, map[string]any) error {
		if fail.Load() {
			return errPostgresAtomicityHook
		}
		return nil
	})
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	_, err = runtime.Register(context.Background(), goauth.RegisterRequest{
		Email: "pg.atomic.claims@example.test", Password: postgresAtomicityPassword,
	})
	require.ErrorIs(t, err, errPostgresAtomicityHook)
	var accounts int
	require.NoError(t, db.QueryRowContext(context.Background(), `SELECT count(*) FROM auth_subjects`).Scan(&accounts))
	require.Zero(t, accounts)
	fail.Store(false)
	registered := register(t, runtime, "pg.atomic.claims@example.test")
	fail.Store(true)
	_, err = runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, errPostgresAtomicityHook)
	fail.Store(false)
	rotated, err := runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.NoError(t, err)
	fail.Store(true)
	_, err = runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrRefreshReplay)
	_, err = runtime.AuthenticateSession(context.Background(), rotated.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

func TestPostgresAuthAtomicityAuditRollback(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	config := runtimeConfig(t)
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	registered := register(t, runtime, "pg.atomic.audit@example.test")
	sso, err := runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer: "https://original.example", Subject: "original", Email: "pg.atomic.link@example.test", EmailVerified: true,
	})
	require.NoError(t, err)
	rejectPostgresAtomicityAuditWrites(t, db)
	for _, operation := range []string{"logout", "logout all", postgresAtomicityStatus, "auto link"} {
		t.Run(operation, func(t *testing.T) {
			switch operation {
			case "logout":
				err = runtime.Logout(context.Background(), registered.Account.Subject.ID, registered.Tokens.Session.ID)
			case "logout all":
				_, err = runtime.LogoutAll(context.Background(), registered.Account.Subject.ID)
			case postgresAtomicityStatus:
				_, err = runtime.SetSubjectStatus(context.Background(), registered.Account.Subject.ID, goauth.SubjectStatusSuspended)
			default:
				_, err = runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
					Issuer: "https://second.example", Subject: "second", Email: "pg.atomic.link@example.test", EmailVerified: true,
				})
			}
			require.ErrorContains(t, err, "postgres_atomicity_reject_audit")
			_, err = runtime.AuthenticateSession(context.Background(), registered.Tokens.AccessToken)
			require.NoError(t, err)
			var status string
			var version int64
			require.NoError(t, db.QueryRowContext(context.Background(),
				`SELECT status,security_version FROM auth_subjects WHERE id=$1`,
				registered.Account.Subject.ID).Scan(&status, &version))
			require.Equal(t, string(registered.Account.Subject.Status), status)
			require.Equal(t, registered.Account.Subject.SecurityVersion, version)
			var links int
			require.NoError(t, db.QueryRowContext(context.Background(),
				`SELECT count(*) FROM auth_identity_links WHERE subject_id=$1`, sso.Subject.ID).Scan(&links))
			require.Equal(t, 1, links)
		})
	}

	allowPostgresAtomicityAuditWrites(t, db)
	require.NoError(t, runtime.Logout(context.Background(), registered.Account.Subject.ID, registered.Tokens.Session.ID))
	_, err = runtime.AuthenticateSession(context.Background(), registered.Tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	var committedAudit int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM auth_security_audit_events WHERE subject_id=$1 AND event_type=$2`,
		registered.Account.Subject.ID, goauth.SecurityEventSessionRevoked).Scan(&committedAudit))
	require.Equal(t, 1, committedAudit)
}

func TestPostgresAuthAtomicityConcurrentRefreshInvalidatesWinner(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "pg.atomic.concurrent@example.test")
	start := make(chan struct{})
	var wait sync.WaitGroup
	type outcome struct {
		pair goauth.TokenPair
		err  error
	}
	results := make(chan outcome, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			pair, err := runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
			results <- outcome{pair, err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var winner goauth.TokenPair
	successes := 0
	for result := range results {
		if result.err == nil {
			successes++
			winner = result.pair
		} else {
			require.ErrorIs(t, result.err, goauth.ErrRefreshReplay)
		}
	}
	require.Equal(t, 1, successes)
	_, err := runtime.AuthenticateSession(context.Background(), winner.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	_, err = runtime.Refresh(context.Background(), winner.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

func TestPostgresAuthAtomicityLogoutDuringClaimsPreparationRejectsSession(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	var armed atomic.Bool
	config := runtimeConfig(t)
	var runtime *postgres.Runtime
	config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
		ctx context.Context, _ goauth.Realm, account goauth.Account, _ map[string]any,
	) error {
		if !armed.CompareAndSwap(true, false) {
			return nil
		}
		_, err := runtime.LogoutAll(ctx, account.Subject.ID)
		return err
	})
	var err error
	runtime, err = postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	registered := register(t, runtime, "pg.atomic.snapshot@example.test")
	armed.Store(true)
	result, err := runtime.Login(context.Background(), login("pg.atomic.snapshot@example.test", postgresAtomicityPassword))
	require.Error(t, err)
	require.Empty(t, result.Tokens.AccessToken)
	var activeSessions int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM auth_sessions WHERE subject_id=$1 AND revoked_at IS NULL`,
		registered.Account.Subject.ID).Scan(&activeSessions))
	require.Zero(t, activeSessions)
}

func TestPostgresAuthAtomicityDownRetainsGenericHostTables(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	_, err := db.ExecContext(context.Background(), `
 CREATE TABLE users (sentinel TEXT NOT NULL);
 CREATE TABLE administrations (sentinel TEXT NOT NULL);
 CREATE TABLE roles (sentinel TEXT NOT NULL);
 CREATE TABLE permissions (sentinel TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS role_hierarchy (sentinel TEXT);
 ALTER TABLE role_hierarchy ADD COLUMN IF NOT EXISTS sentinel TEXT;
 INSERT INTO users VALUES ('preserve');
 INSERT INTO administrations VALUES ('preserve');
 INSERT INTO roles VALUES ('preserve');
 INSERT INTO permissions VALUES ('preserve');
 INSERT INTO role_hierarchy (sentinel) VALUES ('preserve');`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, dropErr := db.ExecContext(context.Background(),
			`DROP TABLE IF EXISTS users, administrations, roles, permissions, role_hierarchy`)
		require.NoError(t, dropErr)
	})
	require.NoError(t, postgres.Down(context.Background(), db, postgres.ConfirmResetAuthState))
	for _, query := range []string{
		`SELECT sentinel FROM users`, `SELECT sentinel FROM administrations`, `SELECT sentinel FROM roles`,
		`SELECT sentinel FROM permissions`, `SELECT sentinel FROM role_hierarchy WHERE sentinel='preserve'`,
	} {
		var sentinel string
		require.NoError(t, db.QueryRowContext(context.Background(), query).Scan(&sentinel))
		require.Equal(t, "preserve", sentinel)
	}
	var canonical sql.NullString
	require.NoError(t, db.QueryRowContext(context.Background(), `SELECT to_regclass('public.auth_subjects')::text`).Scan(&canonical))
	require.False(t, canonical.Valid)
}

func TestPostgresAuthAtomicityVerificationAuditRollback(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	config := runtimeConfig(t)
	events, ok := config.EventSink.(*testkit.EventSink)
	require.True(t, ok)
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	registered := register(t, runtime, "pg.atomic.verification@example.test")
	require.NoError(t, runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification))
	code := integrationNotificationCode(t, runtime, events, "email_challenge")
	rejectPostgresAtomicityAuditWrites(t, db)
	_, err = runtime.VerifyEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification, code)
	require.ErrorContains(t, err, "postgres_atomicity_reject_audit")
	var verified sql.NullTime
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT verified_at FROM auth_identifiers WHERE subject_id=$1`, registered.Account.Subject.ID).Scan(&verified))
	require.False(t, verified.Valid)
	allowPostgresAtomicityAuditWrites(t, db)
	account, err := runtime.VerifyEmailChallenge(context.Background(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification, code)
	require.NoError(t, err)
	require.True(t, account.EmailVerified())
}

func rejectPostgresAtomicityAuditWrites(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE auth_security_audit_events ADD CONSTRAINT postgres_atomicity_reject_audit CHECK(false) NOT VALID`)
	require.NoError(t, err)
}

func allowPostgresAtomicityAuditWrites(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`ALTER TABLE auth_security_audit_events DROP CONSTRAINT postgres_atomicity_reject_audit`)
	require.NoError(t, err)
}
