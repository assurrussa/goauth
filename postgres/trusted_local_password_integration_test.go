//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/postgres"
)

const postgresTrustedSetPassword = "Postgres-Trusted-Set-Passphrase-42"

func TestPostgresTrustedLocalPasswordInvalidatesAllSecurityState(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "trusted.set@example.test")
	id := registered.Account.Subject.ID
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), id, goauth.EmailChallengePurposeVerification))
	require.NoError(t, runtime.RequestEmailChange(t.Context(), id, "changed.set@example.test"))
	require.NoError(t, runtime.RequestPasswordReset(t.Context(), "trusted.set@example.test"))
	oidcStore, err := postgres.NewOIDCRefreshTokenStore(db, keyRing(t, "trusted-oidc", 9))
	require.NoError(t, err)
	now := time.Now().UTC()
	oidcToken := oidc.RefreshToken{
		Token: "trusted-set-oidc-fixture-token", SubjectID: id.String(),
		ClientID: "trusted-set-client", Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
		SecurityVersion: registered.Account.Subject.SecurityVersion, AuthenticatedAt: now, CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, oidcStore.Save(t.Context(), oidcToken))
	account, err := runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: id, NewPassword: postgresTrustedSetPassword,
	})
	require.NoError(t, err)
	require.Equal(t, registered.Account.Subject.Status, account.Subject.Status)
	require.Equal(t, registered.Account.Subject.SecurityVersion+1, account.Subject.SecurityVersion)
	assertTrustedPasswordInvalidated(t, db, id)
	_, err = runtime.VerifyAccessToken(t.Context(), registered.Tokens.AccessToken, true)
	require.Error(t, err)
	_, err = runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	token, err := oidcStore.Get(t.Context(), oidcToken.Token)
	require.NoError(t, err)
	require.NotNil(t, token.RevokedAt)
	_, err = runtime.Login(t.Context(), login("trusted.set@example.test", postgresTrustedSetPassword))
	require.NoError(t, err)
	var audits, deliveries int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_security_audit_events
 WHERE subject_id=$1 AND event_type='password.trusted_set'`, id).Scan(&audits))
	require.Equal(t, 1, audits)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_notification_deliveries
 WHERE subject_id=$1 AND event_type='password_changed'`, id).Scan(&deliveries))
	require.Equal(t, 1, deliveries)
}

func assertTrustedPasswordInvalidated(t *testing.T, db *sql.DB, id goauth.SubjectID) {
	t.Helper()
	for _, query := range []string{
		`SELECT count(*) FROM auth_sessions WHERE subject_id=$1 AND revoked_at IS NULL`,
		`SELECT count(*) FROM auth_refresh_families WHERE subject_id=$1 AND revoked_at IS NULL`,
		`SELECT count(*) FROM auth_oidc_refresh_families WHERE subject_id=$1 AND revoked_at IS NULL`,
		`SELECT count(*) FROM auth_password_reset_records WHERE subject_id=$1 AND consumed_at IS NULL`,
		`SELECT count(*) FROM auth_email_change_records WHERE subject_id=$1 AND consumed_at IS NULL`,
		`SELECT count(*) FROM auth_email_challenges WHERE subject_id=$1 AND verified_at IS NULL AND attempts<max_attempts`,
	} {
		var remaining int
		require.NoError(t, db.QueryRow(query, id).Scan(&remaining))
		require.Zero(t, remaining, query)
	}
}

func TestPostgresTrustedLocalPasswordPreservesInactiveAndRejectsSSO(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	for _, status := range []goauth.SubjectStatus{
		goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled,
	} {
		request := goauth.ImportLocalIdentityRequest{
			SubjectID:           goauth.NewSubjectID(),
			Identifier:          goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "set-" + string(status)},
			PasswordPHC:         postgresLegacyPHC(postgresTrustedSetPassword),
			PasswordInputPolicy: goauth.PasswordInputPolicyLegacyBytes256, Status: status,
		}
		account, err := runtime.ImportLocalIdentity(t.Context(), request)
		require.NoError(t, err)
		for version := int64(2); version <= 3; version++ {
			before, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			updated, err := runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
				SubjectID: account.Subject.ID, NewPassword: postgresTrustedSetPassword,
			})
			require.NoError(t, err)
			require.Equal(t, status, updated.Subject.Status)
			require.Equal(t, version, updated.Subject.SecurityVersion)
			require.Zero(t, updated.PrimaryEmail)
			after, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, goauth.PasswordInputPolicyUnicode, after.PasswordInputPolicy)
			require.NotEqual(t, before.PasswordPHC, after.PasswordPHC)
		}
	}
	sso, err := runtime.ResolveExternalIdentity(t.Context(), goauth.ExternalIdentity{
		Issuer: "https://sso.example.test", Subject: "trusted-set-sso", Email: "sso.set@example.test", EmailVerified: true,
	})
	require.NoError(t, err)
	for _, id := range []goauth.SubjectID{sso.Subject.ID, goauth.NewSubjectID()} {
		account, err := runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
			SubjectID: id, NewPassword: postgresTrustedSetPassword,
		})
		require.ErrorIs(t, err, goauth.ErrAccountNotFound)
		require.Zero(t, account)
	}
	var credentials, deliveries int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_local_credentials`).Scan(&credentials))
	require.Equal(t, 3, credentials)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_notification_deliveries`).Scan(&deliveries))
	require.Zero(t, deliveries)
}

func TestPostgresTrustedLocalPasswordHostRollbackAndAuditFailure(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	original, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "atomic.set@example.test", Password: postgresTrustedSetPassword,
	})
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	before, err := store.GetLocalAccount(t.Context(), original.Subject.ID)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE trusted_set_host_outbox (subject_id uuid, security_version bigint)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := db.Exec(`DROP TABLE trusted_set_host_outbox`); require.NoError(t, err) })
	request := goauth.SetTrustedLocalPasswordRequest{SubjectID: original.Subject.ID, NewPassword: postgresTrustedSetPassword}
	failure := errors.New("host outbox failed")
	for _, rollback := range []bool{true, false} {
		err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			account, err := runtime.SetTrustedLocalPassword(ctx, request)
			if err != nil {
				return err
			}
			executor, err := runtime.SQLExecutor(ctx)
			if err != nil {
				return err
			}
			if _, err := executor.ExecContext(ctx, `INSERT INTO trusted_set_host_outbox VALUES($1,$2)`,
				account.Subject.ID, account.Subject.SecurityVersion); err != nil {
				return err
			}
			if rollback {
				return failure
			}
			return nil
		})
		if rollback {
			require.ErrorIs(t, err, failure)
			after, err := store.GetLocalAccount(t.Context(), original.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, before, after)
			for _, table := range []string{"trusted_set_host_outbox", "auth_security_audit_events", "auth_notification_deliveries"} {
				var count int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
				require.Zero(t, count, table)
			}
		} else {
			require.NoError(t, err)
		}
	}
	before, err = store.GetLocalAccount(t.Context(), original.Subject.ID)
	require.NoError(t, err)
	_, err = db.Exec(`ALTER TABLE auth_security_audit_events ADD CONSTRAINT trusted_set_reject_audit CHECK(false) NOT VALID`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(`ALTER TABLE auth_security_audit_events DROP CONSTRAINT trusted_set_reject_audit`)
		require.NoError(t, err)
	})
	changed, err := runtime.SetTrustedLocalPassword(t.Context(), request)
	require.Error(t, err)
	require.Zero(t, changed)
	after, err := store.GetLocalAccount(t.Context(), original.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	for _, table := range []string{"trusted_set_host_outbox", "auth_security_audit_events", "auth_notification_deliveries"} {
		var count int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
		require.Equal(t, 1, count, table)
	}
}

func TestPostgresTrustedLocalPasswordChecksAllExpectedState(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "guards.set@example.test", Password: postgresTrustedSetPassword,
	})
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	before, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	base := goauth.TrustedLocalPasswordStoreRequest{
		SubjectID:           account.Subject.ID,
		ExpectedPasswordPHC: before.PasswordPHC, ExpectedPasswordInputPolicy: before.PasswordInputPolicy,
		ExpectedSecurityVersion: account.Subject.SecurityVersion, NewPasswordPHC: before.PasswordPHC, Now: time.Now().UTC(),
	}
	for _, field := range []string{"version", "phc", "policy"} {
		stale := base
		expected := goauth.ErrPasswordChangeConflict
		switch field {
		case "version":
			stale.ExpectedSecurityVersion++
			expected = goauth.ErrSecurityVersionMismatch
		case "phc":
			stale.ExpectedPasswordPHC += "stale"
		case "policy":
			stale.ExpectedPasswordInputPolicy = goauth.PasswordInputPolicyLegacyBytes256
		}
		changed, err := store.SetTrustedLocalPassword(t.Context(), stale)
		require.ErrorIs(t, err, expected)
		require.Zero(t, changed)
		after, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
		require.NoError(t, err)
		require.Equal(t, before, after)
	}
}

type postgresTrustedSetBarrierHasher struct {
	goauth.PasswordHasher
	armed   bool
	entered chan struct{}
	release chan struct{}
}

func (h *postgresTrustedSetBarrierHasher) HashPassword(password string) (string, error) {
	if h.armed {
		h.entered <- struct{}{}
		<-h.release
	}
	return h.PasswordHasher.HashPassword(password)
}

func TestPostgresTrustedLocalPasswordConcurrentSetHasOneWinner(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	hasher := &postgresTrustedSetBarrierHasher{PasswordHasher: base, entered: make(chan struct{}, 2), release: make(chan struct{})}
	config := runtimeConfig(t)
	config.PasswordHasher = hasher
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, AutoMigrate: true, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Close()) })
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "two-sets@example.test", Password: postgresTrustedSetPassword,
	})
	require.NoError(t, err)
	hasher.armed = true
	results := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
				SubjectID: account.Subject.ID, NewPassword: postgresTrustedSetPassword,
			})
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-hasher.entered:
		case <-time.After(5 * time.Second):
			close(hasher.release)
			t.Fatal("both setters must hash before any lock")
		}
	}
	close(hasher.release)
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
			conflicts++
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, conflicts)
	stored, err := runtime.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, account.Subject.SecurityVersion+1, stored.Subject.SecurityVersion)
	var audits int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_security_audit_events
 WHERE subject_id=$1 AND event_type='password.trusted_set'`, account.Subject.ID).Scan(&audits))
	require.Equal(t, 1, audits)
}

func TestPostgresTrustedLocalPasswordEnqueueFailureRollsBack(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "enqueue-failure.set@example.test", Password: postgresTrustedSetPassword,
	})
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	before, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	_, err = db.Exec(`ALTER TABLE auth_notification_deliveries ADD CONSTRAINT trusted_set_reject_enqueue CHECK(false) NOT VALID`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(`ALTER TABLE auth_notification_deliveries DROP CONSTRAINT trusted_set_reject_enqueue`)
		require.NoError(t, err)
	})
	changed, err := runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: account.Subject.ID, NewPassword: postgresTrustedSetPassword,
	})
	require.Error(t, err)
	require.Zero(t, changed)
	after, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	for _, table := range []string{"auth_security_audit_events", "auth_notification_deliveries"} {
		var count int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
		require.Zero(t, count)
	}
}

func TestPostgresTrustedLocalPasswordRollbackPreservesSecurityState(t *testing.T) {
	for _, stage := range []string{"host", "audit", "enqueue"} {
		t.Run(stage, func(t *testing.T) {
			db := integrationDB(t)
			runtime, _, _ := integrationRuntime(t, db)
			registered := register(t, runtime, "rollback-state.set@example.test")
			id := registered.Account.Subject.ID
			// Keep rollback assertions intact, then remove only this fixture's
			// account and audit so the following public consumer sees an idle queue.
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err := db.ExecContext(ctx, `DELETE FROM auth_security_audit_events WHERE subject_id=$1`, id)
				require.NoError(t, err)
				_, err = db.ExecContext(ctx, `DELETE FROM auth_subjects WHERE id=$1`, id)
				require.NoError(t, err)
			})
			require.NoError(t, runtime.SendEmailChallenge(t.Context(), id, goauth.EmailChallengePurposeVerification))
			require.NoError(t, runtime.RequestEmailChange(t.Context(), id, "rollback-pending.set@example.test"))
			require.NoError(t, runtime.RequestPasswordReset(t.Context(), registered.Account.PrimaryEmail.DisplayValue))
			now := time.Now().UTC()
			require.NoError(t, runtime.OIDCRefreshTokens().Save(t.Context(), oidc.RefreshToken{
				Token: "rollback-state-oidc-fixture-token", SubjectID: id.String(), ClientID: "rollback-state-client",
				Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}, SecurityVersion: registered.Account.Subject.SecurityVersion,
				AuthenticatedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
			}))
			before := trustedPasswordSecuritySnapshot(t, db, id)
			require.NotEmpty(t, before)
			if stage != "host" {
				table := "auth_security_audit_events"
				if stage == "enqueue" {
					table = "auth_notification_deliveries"
				}
				_, err := db.Exec(`ALTER TABLE ` + table + ` ADD CONSTRAINT trusted_set_state_failure CHECK(false) NOT VALID`)
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := db.Exec(`ALTER TABLE ` + table + ` DROP CONSTRAINT trusted_set_state_failure`)
					require.NoError(t, err)
				})
			}
			failure := errors.New("host state rollback")
			err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
				_, err := runtime.SetTrustedLocalPassword(ctx, goauth.SetTrustedLocalPasswordRequest{
					SubjectID: id, NewPassword: postgresTrustedSetPassword,
				})
				if stage == "host" {
					require.NoError(t, err)
					return failure
				}
				return err
			})
			require.Error(t, err)
			require.Equal(t, before, trustedPasswordSecuritySnapshot(t, db, id))
			_, err = runtime.VerifyAccessToken(t.Context(), registered.Tokens.AccessToken, true)
			require.NoError(t, err)
		})
	}
}

func trustedPasswordSecuritySnapshot(t *testing.T, db *sql.DB, id goauth.SubjectID) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	for _, table := range []string{
		"auth_sessions", "auth_refresh_families", "auth_oidc_refresh_families", "auth_password_reset_records",
		"auth_email_change_records", "auth_email_challenges", "auth_security_audit_events", "auth_notification_deliveries",
	} {
		var state string
		require.NoError(t, db.QueryRow(`SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]'::jsonb)::text
 FROM `+table+` s WHERE subject_id=$1`, id).Scan(&state))
		require.NotEqual(t, "[]", state, "fixture must seed "+table)
		snapshot[table] = state
	}
	return snapshot
}
