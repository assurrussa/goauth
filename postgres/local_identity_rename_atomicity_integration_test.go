//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/testkit"
)

type renameSecurityFixture struct {
	registered goauth.RegisterResult
	oidcToken  string
	resetToken string
	emailCode  string
	changeCode string
}

func seedRenameSecurity(t *testing.T, db *sql.DB, runtime *postgres.Runtime) renameSecurityFixture {
	t.Helper()
	registered := register(t, runtime, "rename-security@example.test")
	id := registered.Account.Subject.ID
	cleanupRenameSubject(t, db, id)
	insertRenameIdentifier(t, db, id, postgresIdentityScheme, "SecurityOriginal", true)
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), id, goauth.EmailChallengePurposeVerification))
	require.NoError(t, runtime.RequestEmailChange(t.Context(), id, "pending.rename-security@example.test"))
	require.NoError(t, runtime.RequestPasswordReset(t.Context(), registered.Account.PrimaryEmail.DisplayValue))
	fixture := renameSecurityFixture{registered: registered, oidcToken: "rename-security-synthetic-oidc-token"}
	now := time.Now().UTC()
	require.NoError(t, runtime.OIDCRefreshTokens().Save(t.Context(), oidc.RefreshToken{
		Token: fixture.oidcToken, SubjectID: id.String(), ClientID: "rename-security-synthetic-client",
		Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}, SecurityVersion: registered.Account.Subject.SecurityVersion,
		AuthenticatedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
	observer := &integrationEventObserver{t: t, db: db}
	for _, event := range observer.Events() {
		notification, err := testkit.DecryptNotification(keyRing(t, "outbox", 3), event.Envelope)
		require.NoError(t, err)
		switch event.Type {
		case "email_challenge":
			fixture.emailCode = notification.Data["code"]
		case "email_change":
			fixture.changeCode = notification.Data["code"]
		case "password_reset":
			parsed, err := url.Parse(notification.Data["reset_url"])
			require.NoError(t, err)
			fixture.resetToken = parsed.Query().Get("token")
		}
	}
	require.NotEmpty(t, fixture.emailCode)
	require.NotEmpty(t, fixture.changeCode)
	require.NotEmpty(t, fixture.resetToken)
	// Existing shared helper also verifies that all security-state tables were seeded.
	_ = trustedPasswordSecuritySnapshot(t, db, id)
	return fixture
}

func TestPostgresLocalIdentityRenameInvalidatesAllSecurityStateWithoutNotification(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	fixture := seedRenameSecurity(t, db, runtime)
	id := fixture.registered.Account.Subject.ID
	before := renameIdentitySnapshot(t, db, id)
	storedBefore, err := runtime.GetAccount(t.Context(), id)
	require.NoError(t, err)
	view, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(fixture.registered.Account, "SecurityOriginal", "SecurityRenamed"))
	require.NoError(t, err)
	require.Equal(t, fixture.registered.Account.Subject.SecurityVersion+1, view.Account.Subject.SecurityVersion)
	require.Equal(t, storedBefore.PrimaryEmail, view.Account.PrimaryEmail)
	assertTrustedPasswordInvalidated(t, db, id)
	after := renameIdentitySnapshot(t, db, id)
	require.Equal(t, before["auth_local_credentials"], after["auth_local_credentials"])
	require.Equal(t, before["auth_notification_deliveries"], after["auth_notification_deliveries"], "rename emits mandatory audit without an email delivery")
	var attributes string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT attributes::text FROM auth_security_audit_events
 WHERE subject_id=$1 AND event_type=$2`, id, goauth.SecurityEventLocalIdentityRenamed).Scan(&attributes))
	for _, secret := range []string{
		"SecurityOriginal", "SecurityRenamed", fixture.oidcToken, fixture.resetToken, fixture.emailCode, fixture.changeCode,
		"Integration-Unique-Passphrase-1", "$argon2id$",
	} {
		require.NotContains(t, attributes, secret)
	}
	for _, toggle := range []bool{false, true} {
		if toggle {
			_, err := runtime.SetSubjectStatus(t.Context(), id, goauth.SubjectStatusDisabled)
			require.NoError(t, err)
			_, err = runtime.SetSubjectStatus(t.Context(), id, goauth.SubjectStatusActive)
			require.NoError(t, err)
		}
		_, err := runtime.VerifyAccessToken(t.Context(), fixture.registered.Tokens.AccessToken, true)
		require.Error(t, err)
		_, err = runtime.Refresh(t.Context(), fixture.registered.Tokens.RefreshToken)
		require.ErrorIs(t, err, goauth.ErrSessionRevoked)
		token, err := runtime.OIDCRefreshTokens().Get(t.Context(), fixture.oidcToken)
		require.NoError(t, err)
		require.NotNil(t, token.RevokedAt)
		require.Error(t, runtime.ResetPassword(t.Context(), fixture.resetToken, "Unused-Rename-Reset-Passphrase-42"))
		_, err = runtime.ConfirmEmailChange(t.Context(), id, fixture.changeCode)
		require.Error(t, err)
		_, err = runtime.VerifyEmailChallenge(t.Context(), id, goauth.EmailChallengePurposeVerification, fixture.emailCode)
		require.Error(t, err)
		assertTrustedPasswordInvalidated(t, db, id)
	}
}

func TestPostgresLocalIdentityRenameEveryInvalidationAndAuditFailureRollsBack(t *testing.T) {
	for _, stage := range []struct{ table, predicate string }{
		{"auth_sessions", "revoked_at IS NULL"},
		{"auth_refresh_families", "revoked_at IS NULL"},
		{"auth_oidc_refresh_families", "revoked_at IS NULL"},
		{"auth_email_change_records", "consumed_at IS NULL"},
		{"auth_email_challenges", "attempts < max_attempts"},
		{"auth_password_reset_records", "consumed_at IS NULL"},
		{"auth_security_audit_events", "event_type <> 'local_identity.renamed'"},
	} {
		t.Run(stage.table, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := renamePostgresRuntime(t, db, nil)
			fixture := seedRenameSecurity(t, db, runtime)
			id := fixture.registered.Account.Subject.ID
			before := renameIdentitySnapshot(t, db, id)
			_, err := db.Exec(`ALTER TABLE ` + stage.table + ` ADD CONSTRAINT rename_reject_mutation CHECK (` + stage.predicate + `) NOT VALID`)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := db.Exec(`ALTER TABLE ` + stage.table + ` DROP CONSTRAINT rename_reject_mutation`)
				require.NoError(t, err)
			})
			view, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(fixture.registered.Account, "SecurityOriginal", "SecurityRenamed"))
			require.Error(t, err)
			require.Zero(t, view)
			require.Equal(t, before, renameIdentitySnapshot(t, db, id), "every mutation before the injected failure must roll back")
			_, err = runtime.VerifyAccessToken(t.Context(), fixture.registered.Tokens.AccessToken, true)
			require.NoError(t, err)
		})
	}
}

func TestPostgresLocalIdentityRenameJoinsOuterHostTransactionAndRejectsForeignContext(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	fixture := seedRenameSecurity(t, db, runtime)
	id := fixture.registered.Account.Subject.ID
	before := renameIdentitySnapshot(t, db, id)
	_, err := db.Exec(`CREATE TABLE rename_host_receipt (subject_id uuid PRIMARY KEY, security_version bigint NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := db.Exec(`DROP TABLE rename_host_receipt`); require.NoError(t, err) })
	failure := errors.New("synthetic host audit rejected")
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		err := runtime.InAuthTransaction(ctx, func(inner context.Context) error {
			view, err := runtime.RenameLocalIdentity(inner, renameRequest(fixture.registered.Account, "SecurityOriginal", "SecurityRenamed"))
			if err != nil {
				return err
			}
			read, err := runtime.GetLocalIdentifier(inner, id, postgresIdentityScheme)
			if err != nil {
				return err
			}
			assertRenameIdentifierPersisted(t, view.Identifier, read)
			executor, err := runtime.SQLExecutor(inner)
			if err != nil {
				return err
			}
			_, err = executor.ExecContext(inner, `INSERT INTO rename_host_receipt VALUES($1,$2)`, id, view.Account.Subject.SecurityVersion)
			return err
		})
		if err != nil {
			return err
		}
		// The nested result is provisional: another connection still reads old committed state.
		require.Equal(t, before, renameIdentitySnapshot(t, db, id))
		return failure
	})
	require.ErrorIs(t, err, failure)
	require.Equal(t, before, renameIdentitySnapshot(t, db, id))
	var receipts int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM rename_host_receipt`).Scan(&receipts))
	require.Zero(t, receipts)
	foreignDB := integrationDB(t)
	foreign := renamePostgresRuntime(t, foreignDB, nil)
	require.NoError(t, foreign.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		view, err := runtime.RenameLocalIdentity(ctx, renameRequest(fixture.registered.Account, "SecurityOriginal", "SecurityRenamed"))
		require.ErrorContains(t, err, "different database handle")
		require.Zero(t, view)
		identifier, err := runtime.GetLocalIdentifier(ctx, id, postgresIdentityScheme)
		require.Error(t, err)
		require.Zero(t, identifier)
		return nil
	}))
	require.Equal(t, before, renameIdentitySnapshot(t, db, id))
}
