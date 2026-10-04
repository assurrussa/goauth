//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/testkit"
)

const postgresIdentityScheme goauth.IdentifierScheme = "hub_login"

func identityPostgresRuntime(t *testing.T, db *sql.DB) *postgres.Runtime {
	t.Helper()
	config := runtimeConfig(t)
	config.EnableLegacyBytes256 = true
	config.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
		postgresIdentityScheme: goauth.IdentifierResolverFunc(func(
			_ context.Context, input goauth.IdentifierInput,
		) (goauth.IdentifierInput, error) {
			return input, nil
		}),
	}
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, AutoMigrate: true, Runtime: config, NotificationSender: integrationNotificationSender()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Close()) })
	return runtime
}

func postgresLegacyPHC(password string) string {
	salt := bytes.Repeat([]byte{73}, 16)
	digest := argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32)
	return "$argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(digest)
}

func TestPostgresLocalIdentityImportJoinsHostMappingAndGrant(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	_, err := db.Exec(`CREATE TABLE identity_import_map (legacy_login text PRIMARY KEY, subject_id uuid UNIQUE REFERENCES auth_subjects(id));
 CREATE TABLE identity_project_access (subject_id uuid REFERENCES auth_subjects(id), project_id text, access_version bigint, PRIMARY KEY(subject_id, project_id));`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(`DROP TABLE identity_project_access; DROP TABLE identity_import_map`)
		require.NoError(t, err)
	})
	password := string([]byte{'p', 0xff, 0, 'a'}) + strings.Repeat("x", 129)
	request := goauth.ImportLocalIdentityRequest{
		SubjectID:  goauth.NewSubjectID(),
		Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "Operator"}, PasswordPHC: postgresLegacyPHC(password),
		PasswordInputPolicy: goauth.PasswordInputPolicyLegacyBytes256, Status: goauth.SubjectStatusActive,
	}
	stopped := errors.New("host write failed")
	var account goauth.Account
	migrate := func(stop bool) error {
		return runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			executor, err := runtime.SQLExecutor(ctx)
			if err != nil {
				return err
			}
			// Host import coordination lock always precedes canonical subject locks.
			if _, err := executor.ExecContext(ctx, `SELECT pg_advisory_xact_lock(921017)`); err != nil {
				return err
			}
			var mapped goauth.SubjectID
			err = executor.QueryRowContext(ctx, `SELECT subject_id FROM identity_import_map WHERE legacy_login=$1`, request.Identifier.Value).Scan(&mapped)
			if err == nil {
				account, err = runtime.GetAccount(ctx, mapped)
				return err
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			account, err = runtime.ImportLocalIdentity(ctx, request)
			if err != nil {
				return err
			}
			if _, err := executor.ExecContext(ctx, `INSERT INTO identity_import_map VALUES ($1,$2)`, request.Identifier.Value, account.Subject.ID); err != nil {
				return err
			}
			if _, err := executor.ExecContext(ctx, `INSERT INTO identity_project_access VALUES ($1,'project-a',1)`, account.Subject.ID); err != nil {
				return err
			}
			if stop {
				return stopped
			}
			return nil
		})
	}
	require.ErrorIs(t, migrate(true), stopped)
	for _, table := range []string{"auth_subjects", "auth_local_credentials", "auth_identifiers", "auth_security_audit_events", "identity_import_map", "identity_project_access"} {
		var count int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&count))
		require.Zero(t, count, table)
	}
	require.NoError(t, migrate(false))
	require.Equal(t, request.SubjectID, account.Subject.ID)
	require.Zero(t, account.PrimaryEmail)
	found, err := runtime.FindAccount(t.Context(), request.Identifier)
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, found.Subject.ID)
	proof, err := runtime.PrepareCredential(t.Context(), goauth.Credential{
		Identifier: request.Identifier,
		Password:   password,
	})
	require.NoError(t, err)
	require.NoError(t, runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		verified, err := runtime.RevalidateCredential(ctx, proof)
		require.Equal(t, account.Subject.ID, verified.Subject.ID)
		require.Zero(t, verified.PrimaryEmail)
		return err
	}))
	changed, err := runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID:       account.Subject.ID,
		CurrentPassword: password,
		NewPassword:     "Changed-Canonical-Passphrase-42",
	})
	require.NoError(t, err)
	require.EqualValues(t, 2, changed.Subject.SecurityVersion)
	_, err = runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
	require.NoError(t, err)
	require.NoError(t, migrate(false), "mapped retry must not restore an old password or disabled state")
	require.Equal(t, goauth.SubjectStatusDisabled, account.Subject.Status)
	require.EqualValues(t, 3, account.Subject.SecurityVersion)
	var policy, phc string
	require.NoError(t, db.QueryRow(`SELECT password_input_policy,password_phc FROM auth_local_credentials WHERE subject_id=$1`, account.Subject.ID).Scan(&policy, &phc))
	require.Equal(t, string(goauth.PasswordInputPolicyUnicode), policy)
	require.NotEqual(t, request.PasswordPHC, phc)
	var imports, grants, deliveries int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_security_audit_events WHERE event_type='local_identity.imported'`).Scan(&imports))
	require.Equal(t, 1, imports)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM identity_project_access WHERE access_version=1`).Scan(&grants))
	require.Equal(t, 1, grants)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_notification_deliveries`).Scan(&deliveries))
	require.Zero(t, deliveries)
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error { _, err := runtime.RevalidateCredential(ctx, proof); return err })
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
}

func TestPostgresLocalIdentityImportDoesNotMergeOperator(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	operator, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email:    "operator@example.test",
		Password: "Operator-Original-Passphrase-42",
		Profile:  goauth.BasicProfile{Username: "Operator"},
	})
	require.NoError(t, err)
	request := goauth.ImportLocalIdentityRequest{
		SubjectID: goauth.NewSubjectID(), Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "Operator"},
		PasswordPHC: postgresLegacyPHC("Legacy-Passphrase-42"), PasswordInputPolicy: goauth.PasswordInputPolicyLegacyBytes256, Status: goauth.SubjectStatusDisabled,
	}
	imported, err := runtime.ImportLocalIdentity(t.Context(), request)
	require.NoError(t, err)
	require.NotEqual(t, operator.Subject.ID, imported.Subject.ID)
	require.Zero(t, imported.PrimaryEmail)
	require.Equal(t, goauth.SubjectStatusDisabled, imported.Subject.Status)
	_, err = runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	request.SubjectID = goauth.NewSubjectID()
	_, err = runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	request.SubjectID = operator.Subject.ID
	request.Identifier.Value = "NewLogin"
	_, err = runtime.ImportLocalIdentity(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	var subjects, credentials int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_subjects`).Scan(&subjects))
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_local_credentials`).Scan(&credentials))
	require.Equal(t, 2, subjects)
	require.Equal(t, 2, credentials)
}

func TestPostgresLocalIdentityProvisionAuditFailureRollsBack(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	_, err := db.Exec(`ALTER TABLE auth_security_audit_events ADD CONSTRAINT identity_reject_audit CHECK(false) NOT VALID`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(`ALTER TABLE auth_security_audit_events DROP CONSTRAINT identity_reject_audit`)
		require.NoError(t, err)
	})
	account, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "failed"},
		Password:   "Audit-Failure-Passphrase-42",
	})
	require.Error(t, err)
	require.Zero(t, account)
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_subjects`).Scan(&count))
	require.Zero(t, count)
}

func TestPostgresLocalIdentityMigrationPreservesV3(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email:    "upgrade@example.test",
		Password: "Upgrade-Original-Passphrase-42",
	})
	require.NoError(t, err)
	_, err = runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
	require.NoError(t, err)
	var previousPHC string
	require.NoError(t, db.QueryRow(`SELECT password_phc FROM auth_local_credentials WHERE subject_id=$1`, account.Subject.ID).Scan(&previousPHC))
	removeSessionOIDCSchema(t, db)
	_, err = db.Exec(`ALTER TABLE auth_subjects DROP COLUMN retired_at;
ALTER TABLE auth_local_credentials DROP COLUMN password_input_policy;
DROP INDEX auth_notification_deliveries_expiry_idx;
DROP INDEX auth_rate_limit_events_retention_idx;
DELETE FROM goauth_migration_history WHERE version >= 4;
DELETE FROM goauth_schema_version WHERE version >= 4`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, postgres.Migrate(t.Context(), db))
	var phc, policy, status string
	var version int64
	require.NoError(t, db.QueryRow(`SELECT c.password_phc,c.password_input_policy,s.status,s.security_version FROM auth_subjects s JOIN auth_local_credentials c ON c.subject_id=s.id WHERE s.id=$1`, account.Subject.ID).Scan(&phc, &policy, &status, &version))
	require.Equal(t, previousPHC, phc)
	require.Equal(t, string(goauth.PasswordInputPolicyUnicode), policy)
	require.Equal(t, string(goauth.SubjectStatusDisabled), status)
	require.EqualValues(t, 2, version)
	_, err = db.Exec(`UPDATE goauth_migration_history SET checksum='altered' WHERE version=4`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaChecksumMismatch)
	require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaChecksumMismatch)
}

func TestPostgresPasswordResetClearsLegacyInputPolicy(t *testing.T) {
	db := integrationDB(t)
	runtime, events, keys := integrationRuntime(t, db)
	registered := register(t, runtime, "legacy-reset@example.test")
	_, err := db.Exec(`UPDATE auth_local_credentials SET password_phc=$2,password_input_policy='legacy_bytes_256' WHERE subject_id=$1`, registered.Account.Subject.ID, postgresLegacyPHC("Legacy-Passphrase-42"))
	require.NoError(t, err)
	require.NoError(t, runtime.RequestPasswordReset(t.Context(), "legacy-reset@example.test"))
	all := events.Events()
	notification, err := testkit.DecryptNotification(keys, all[len(all)-1].Envelope)
	require.NoError(t, err)
	parsed, err := url.Parse(notification.Data["reset_url"])
	require.NoError(t, err)
	require.NoError(t, runtime.ResetPassword(t.Context(), parsed.Query().Get("token"), "Reset-Current-Policy-Passphrase-42"))
	var policy string
	require.NoError(t, db.QueryRow(`SELECT password_input_policy FROM auth_local_credentials WHERE subject_id=$1`, registered.Account.Subject.ID).Scan(&policy))
	require.Equal(t, string(goauth.PasswordInputPolicyUnicode), policy)
}

func TestPostgresLocalIdentityLookupDoesNotEnableSecondaryAliases(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	const password = "Primary-Only-Lookup-Passphrase-42"
	email, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "primary@example.test", Password: password,
	})
	require.NoError(t, err)
	custom, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "PrimaryLogin"}, Password: password,
	})
	require.NoError(t, err)
	for _, test := range []struct {
		account            goauth.Account
		scheme             goauth.IdentifierScheme
		primary, secondary string
	}{
		{email, goauth.IdentifierSchemeEmail, "primary@example.test", "secondary@example.test"},
		{custom, postgresIdentityScheme, "PrimaryLogin", "SecondaryLogin"},
	} {
		_, err := db.Exec(`INSERT INTO auth_identifiers
   (id,subject_id,scheme,display_value,normalized_value,is_primary,created_at,updated_at)
   VALUES ($1,$2,$3,$4,$4,false,now(),now())`, goauth.NewSubjectID(), test.account.Subject.ID, test.scheme, test.secondary)
		require.NoError(t, err)
		primary := goauth.IdentifierInput{Scheme: test.scheme, Value: test.primary}
		found, err := runtime.FindAccount(t.Context(), primary)
		require.NoError(t, err)
		require.Equal(t, test.account.Subject.ID, found.Subject.ID)
		verified, err := runtime.VerifyCredential(t.Context(), goauth.Credential{Identifier: primary, Password: password})
		require.NoError(t, err)
		require.Equal(t, test.account.Subject.ID, verified.Subject.ID)
		secondary := goauth.IdentifierInput{Scheme: test.scheme, Value: test.secondary}
		_, err = runtime.FindAccount(t.Context(), secondary)
		require.ErrorIs(t, err, goauth.ErrAccountNotFound)
		_, err = runtime.VerifyCredential(t.Context(), goauth.Credential{Identifier: secondary, Password: password})
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	}
}
