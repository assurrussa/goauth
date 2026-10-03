//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestPostgresSubjectRetirementInvalidatesSecurityWithoutNotification(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	fixture := seedRenameSecurity(t, db, runtime)
	id := fixture.registered.Account.Subject.ID
	before := renameIdentitySnapshot(t, db, id)
	view, err := runtime.RetireLocalIdentity(t.Context(), retirementRequest(fixture.registered.Account, "SecurityOriginal"))
	require.NoError(t, err)
	require.Equal(t, fixture.registered.Account.Subject.SecurityVersion+1, view.Account.Subject.SecurityVersion)
	assertTrustedPasswordInvalidated(t, db, id)
	after := renameIdentitySnapshot(t, db, id)
	require.Equal(t, before["auth_notification_deliveries"], after["auth_notification_deliveries"])
	var attributes string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT attributes::text FROM auth_security_audit_events
 WHERE subject_id=$1 AND event_type=$2`, id, goauth.SecurityEventSubjectRetired).Scan(&attributes))
	for _, secret := range []string{
		"SecurityOriginal", fixture.oidcToken, fixture.resetToken, fixture.emailCode, fixture.changeCode,
		"Integration-Unique-Passphrase-1", "$argon2id$",
	} {
		require.NotContains(t, attributes, secret)
	}
	provisionRenameIdentity(t, db, runtime, "SecurityOriginal")
	_, err = runtime.VerifyAccessToken(t.Context(), fixture.registered.Tokens.AccessToken, true)
	require.Error(t, err)
	_, err = runtime.Refresh(t.Context(), fixture.registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	token, err := runtime.OIDCRefreshTokens().Get(t.Context(), fixture.oidcToken)
	require.NoError(t, err)
	require.NotNil(t, token.RevokedAt)
	require.Error(t, runtime.ResetPassword(t.Context(), fixture.resetToken, "Retirement-Reset-Synthetic-Passphrase-42"))
	_, err = runtime.ConfirmEmailChange(t.Context(), id, fixture.changeCode)
	require.Error(t, err)
	_, err = runtime.VerifyEmailChallenge(t.Context(), id, goauth.EmailChallengePurposeVerification, fixture.emailCode)
	require.Error(t, err)
	assertTrustedPasswordInvalidated(t, db, id)
}

func TestPostgresSubjectRetirementEveryWriteFailureRollsBack(t *testing.T) {
	for _, stage := range []struct{ table, predicate string }{
		{"auth_subjects", "retired_at IS NULL"},
		{"auth_identifiers", "DELETE"},
		{"auth_local_credentials", "DELETE"},
		{"auth_sessions", "revoked_at IS NULL"},
		{"auth_refresh_families", "revoked_at IS NULL"},
		{"auth_oidc_refresh_families", "revoked_at IS NULL"},
		{"auth_email_change_records", "consumed_at IS NULL"},
		{"auth_email_challenges", "attempts < max_attempts"},
		{"auth_password_reset_records", "consumed_at IS NULL"},
		{"auth_security_audit_events", "event_type <> 'subject.retired'"},
	} {
		t.Run(stage.table, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := renamePostgresRuntime(t, db, nil)
			fixture := seedRenameSecurity(t, db, runtime)
			id := fixture.registered.Account.Subject.ID
			before := renameIdentitySnapshot(t, db, id)
			if stage.predicate == "DELETE" {
				_, err := db.Exec(`CREATE FUNCTION retirement_reject_delete() RETURNS trigger LANGUAGE plpgsql AS
 $$ BEGIN RAISE EXCEPTION 'synthetic retirement delete failed'; END $$;
 CREATE TRIGGER retirement_reject_delete BEFORE DELETE ON ` + stage.table + `
 FOR EACH ROW EXECUTE FUNCTION retirement_reject_delete()`)
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := db.Exec(`DROP TRIGGER retirement_reject_delete ON ` + stage.table + `; DROP FUNCTION retirement_reject_delete()`)
					require.NoError(t, err)
				})
			} else {
				_, err := db.Exec(`ALTER TABLE ` + stage.table + ` ADD CONSTRAINT retirement_reject_mutation CHECK (` + stage.predicate + `) NOT VALID`)
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := db.Exec(`ALTER TABLE ` + stage.table + ` DROP CONSTRAINT retirement_reject_mutation`)
					require.NoError(t, err)
				})
			}
			view, err := runtime.RetireLocalIdentity(t.Context(), retirementRequest(fixture.registered.Account, "SecurityOriginal"))
			require.Error(t, err)
			require.Zero(t, view)
			require.Equal(t, before, renameIdentitySnapshot(t, db, id))
			_, err = runtime.VerifyAccessToken(t.Context(), fixture.registered.Tokens.AccessToken, true)
			require.NoError(t, err)
		})
	}
}

func TestPostgresSubjectRetirementJoinsHostGrantOutboxStubAndReceipt(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	fixture := seedRenameSecurity(t, db, runtime)
	id := fixture.registered.Account.Subject.ID
	_, err := db.Exec(`CREATE TABLE retirement_host_grant(subject_id uuid PRIMARY KEY,version bigint NOT NULL, revoked bool NOT NULL);
 CREATE TABLE retirement_host_outbox_stub(subject_id uuid PRIMARY KEY);
 CREATE TABLE retirement_host_receipt(subject_id uuid PRIMARY KEY,security_version bigint NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(`DROP TABLE retirement_host_grant,retirement_host_outbox_stub,retirement_host_receipt`)
		require.NoError(t, err)
	})
	_, err = db.Exec(`INSERT INTO retirement_host_grant VALUES($1,1,false)`, id)
	require.NoError(t, err)
	before := renameIdentitySnapshot(t, db, id)
	failure := errors.New("host composition rollback")
	for _, stop := range []string{"grant", "outbox", "receipt", "commit"} {
		t.Run(stop, func(t *testing.T) {
			err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
				view, err := runtime.RetireLocalIdentity(ctx, retirementRequest(fixture.registered.Account, "SecurityOriginal"))
				if err != nil {
					return err
				}
				read, err := runtime.GetSubjectLifecycle(ctx, id)
				if err != nil {
					return err
				}
				require.Equal(t, view, read)
				require.Equal(t, before, renameIdentitySnapshot(t, db, id), "nested success is provisional")
				executor, err := runtime.SQLExecutor(ctx)
				if err != nil {
					return err
				}
				if _, err = executor.ExecContext(ctx, `UPDATE retirement_host_grant SET version=version+1,revoked=true WHERE subject_id=$1`, id); err != nil {
					return err
				}
				if stop == "grant" {
					return failure
				}
				if _, err = executor.ExecContext(ctx, `INSERT INTO retirement_host_outbox_stub VALUES($1)`, id); err != nil {
					return err
				}
				if stop == "outbox" {
					return failure
				}
				if _, err = executor.ExecContext(ctx, `INSERT INTO retirement_host_receipt VALUES($1,$2)`, id, view.Account.Subject.SecurityVersion); err != nil {
					return err
				}
				if stop == "receipt" {
					return failure
				}
				return nil
			})
			var version, receipts, outbox int
			var revoked bool
			require.NoError(t, db.QueryRow(`SELECT version,revoked FROM retirement_host_grant WHERE subject_id=$1`, id).Scan(&version, &revoked))
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM retirement_host_receipt`).Scan(&receipts))
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM retirement_host_outbox_stub`).Scan(&outbox))
			if stop != "commit" {
				require.ErrorIs(t, err, failure)
				require.Equal(t, 1, version)
				require.False(t, revoked)
				require.Zero(t, receipts)
				require.Zero(t, outbox)
				require.Equal(t, before, renameIdentitySnapshot(t, db, id))
			} else {
				require.NoError(t, err)
				require.Equal(t, 2, version)
				require.True(t, revoked)
				require.Equal(t, 1, receipts)
				require.Equal(t, 1, outbox)
				assertTrustedPasswordInvalidated(t, db, id)
			}
		})
	}
}
