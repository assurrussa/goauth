//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

const postgresRenamePassword = "Postgres-Rename-Synthetic-Passphrase-42"

func renamePostgresRuntime(t *testing.T, db *sql.DB, configure func(*goauth.Config)) *postgres.Runtime {
	t.Helper()
	config := runtimeConfig(t)
	config.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
		postgresIdentityScheme: goauth.IdentifierResolverFunc(func(_ context.Context, input goauth.IdentifierInput) (goauth.IdentifierInput, error) {
			return input, nil
		}),
	}
	if configure != nil {
		configure(&config)
	}
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, AutoMigrate: true, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		// Tests reset an isolated schema first. Identifier-admission rows have no
		// subject FK, so they cannot cascade with the fixture's subjects.
		_, err := db.ExecContext(context.Background(), `DELETE FROM auth_rate_limit_events WHERE subject_id IS NULL`)
		require.NoError(t, err)
		require.NoError(t, runtime.Close())
	})
	return runtime
}

func cleanupRenameSubject(t *testing.T, db *sql.DB, id goauth.SubjectID) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Audit deliberately uses ON DELETE SET NULL, so remove this fixture's
		// audit before cascading the subject-owned security and notification rows.
		_, err := db.ExecContext(ctx, `DELETE FROM auth_security_audit_events WHERE subject_id=$1`, id)
		require.NoError(t, err)
		_, err = db.ExecContext(ctx, `DELETE FROM auth_subjects WHERE id=$1`, id)
		require.NoError(t, err)
	})
}

func provisionRenameIdentity(t *testing.T, db *sql.DB, runtime *postgres.Runtime, value string) goauth.Account {
	t.Helper()
	account, err := runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: value}, Password: postgresRenamePassword,
		Profile: goauth.BasicProfile{Username: "profile-name", DisplayName: "Synthetic Operator"},
	})
	require.NoError(t, err)
	cleanupRenameSubject(t, db, account.Subject.ID)
	return account
}

func renameRequest(account goauth.Account, oldValue, newValue string) goauth.RenameLocalIdentityRequest {
	return goauth.RenameLocalIdentityRequest{
		SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
		ExpectedIdentifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: oldValue},
		NewIdentifier:      goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: newValue},
	}
}

func insertRenameIdentifier(t *testing.T, db *sql.DB, id goauth.SubjectID, scheme goauth.IdentifierScheme, value string, primary bool) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `INSERT INTO auth_identifiers
 (id,subject_id,scheme,display_value,normalized_value,is_primary,created_at,updated_at)
 VALUES ($1,$2,$3,$4,$4,$5,now(),now())`, goauth.NewSubjectID(), id, scheme, value, primary)
	require.NoError(t, err)
}

func renameIdentitySnapshot(t *testing.T, db *sql.DB, id goauth.SubjectID) map[string]string {
	t.Helper()
	state := make(map[string]string)
	for _, table := range []string{
		"auth_subjects", "auth_identifiers", "auth_local_credentials", "auth_basic_profiles", "auth_identity_links", "auth_subject_roles",
		"auth_sessions", "auth_refresh_families", "auth_oidc_refresh_families", "auth_password_reset_records",
		"auth_email_change_records", "auth_email_challenges", "auth_security_audit_events", "auth_notification_deliveries",
	} {
		key := "subject_id"
		if table == "auth_subjects" {
			key = "id"
		}
		var value string
		require.NoError(t, db.QueryRowContext(t.Context(), `SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]'::jsonb)::text
 FROM `+table+` s WHERE `+key+`=$1`, id).Scan(&value))
		state[table] = value
	}
	return state
}

func renameAuditCount(t *testing.T, db *sql.DB, id goauth.SubjectID) int {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_security_audit_events
 WHERE subject_id=$1 AND event_type=$2`, id, goauth.SecurityEventLocalIdentityRenamed).Scan(&count))
	return count
}

func TestPostgresGetLocalIdentifierIsPrimaryOnlyAndIndependentOfCredential(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	account := provisionRenameIdentity(t, db, runtime, "PrimaryRead")
	insertRenameIdentifier(t, db, account.Subject.ID, postgresIdentityScheme, "SecondaryRead", false)
	identifier, err := runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, postgresIdentityScheme)
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, identifier.SubjectID)
	require.Equal(t, "PrimaryRead", identifier.DisplayValue)
	require.Equal(t, "PrimaryRead", identifier.NormalizedValue)
	require.Nil(t, identifier.VerifiedAt)
	_, err = db.ExecContext(t.Context(), `UPDATE auth_identifiers SET is_primary=false WHERE id=$1`, identifier.ID)
	require.NoError(t, err)
	missing, err := runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, postgresIdentityScheme)
	require.ErrorIs(t, err, goauth.ErrLocalIdentifierConflict, "a secondary alias must never become the operator read model")
	require.Zero(t, missing)
	_, err = db.ExecContext(t.Context(), `UPDATE auth_identifiers SET is_primary=true WHERE id=$1`, identifier.ID)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `DELETE FROM auth_local_credentials WHERE subject_id=$1`, account.Subject.ID)
	require.NoError(t, err)
	missing, err = runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, postgresIdentityScheme)
	require.NoError(t, err, "the non-secret primary read does not require credential material")
	require.Equal(t, identifier, missing)
	missing, err = runtime.GetLocalIdentifier(t.Context(), goauth.NewSubjectID(), postgresIdentityScheme)
	require.ErrorIs(t, err, goauth.ErrLocalIdentifierConflict)
	require.Zero(t, missing)
}

func TestPostgresLocalIdentityRenamePreservesCanonicalIdentityAndGrants(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	t.Cleanup(func() {
		_, err := db.Exec(`DELETE FROM auth_rate_limit_events WHERE subject_id IS NULL`)
		require.NoError(t, err)
	})
	phc := postgresLegacyPHC(postgresRenamePassword)
	var roleID int64
	require.NoError(t, db.QueryRowContext(t.Context(), `INSERT INTO auth_roles(public_id,slug,name)
 VALUES($1,'rename-fixture-role','Rename fixture') RETURNING id`, goauth.NewSubjectID()).Scan(&roleID))
	t.Cleanup(func() { _, err := db.Exec(`DELETE FROM auth_roles WHERE id=$1`, roleID); require.NoError(t, err) })
	for _, status := range []goauth.SubjectStatus{goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled} {
		t.Run(string(status), func(t *testing.T) {
			oldValue := "Original-" + string(status)
			account, err := runtime.ImportLocalIdentity(t.Context(), goauth.ImportLocalIdentityRequest{
				SubjectID: goauth.NewSubjectID(), Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: oldValue},
				PasswordPHC: phc, PasswordInputPolicy: goauth.PasswordInputPolicyLegacyBytes256, Status: status,
				Profile: goauth.BasicProfile{Username: "separate-profile", DisplayName: "Synthetic Rename"},
			})
			require.NoError(t, err)
			cleanupRenameSubject(t, db, account.Subject.ID)
			insertRenameIdentifier(t, db, account.Subject.ID, goauth.IdentifierSchemeEmail, string(status)+".rename@example.test", true)
			_, err = db.ExecContext(t.Context(), `UPDATE auth_identifiers SET verified_at=created_at WHERE subject_id=$1 AND scheme='email'`, account.Subject.ID)
			require.NoError(t, err)
			_, err = db.ExecContext(t.Context(), `INSERT INTO auth_subject_roles(subject_id,role_id) VALUES($1,$2)`, account.Subject.ID, roleID)
			require.NoError(t, err)
			_, err = db.ExecContext(t.Context(), `INSERT INTO auth_identity_links(id,subject_id,issuer,external_subject,created_at,updated_at)
 VALUES($1,$2,'https://rename.example.test',$3,now(),now())`, goauth.NewSubjectID(), account.Subject.ID, oldValue)
			require.NoError(t, err)
			before, err := runtime.GetAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			identifier, err := runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, postgresIdentityScheme)
			require.NoError(t, err)
			snapshot := renameIdentitySnapshot(t, db, account.Subject.ID)
			view, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(before, oldValue, "Renamed-"+string(status)))
			require.NoError(t, err)
			require.Equal(t, before.Subject.ID, view.Account.Subject.ID)
			require.Equal(t, status, view.Account.Subject.Status)
			require.Equal(t, before.Subject.SecurityVersion+1, view.Account.Subject.SecurityVersion)
			require.Equal(t, before.Subject.CreatedAt, view.Account.Subject.CreatedAt)
			require.Equal(t, before.Profile, view.Account.Profile)
			require.Equal(t, before.PrimaryEmail, view.Account.PrimaryEmail)
			require.Equal(t, identifier.ID, view.Identifier.ID)
			require.Equal(t, identifier.CreatedAt, view.Identifier.CreatedAt)
			require.Equal(t, identifier.SubjectID, view.Identifier.SubjectID)
			require.Equal(t, identifier.VerifiedAt, view.Identifier.VerifiedAt)
			after := renameIdentitySnapshot(t, db, account.Subject.ID)
			for _, table := range []string{"auth_local_credentials", "auth_basic_profiles", "auth_identity_links", "auth_subject_roles"} {
				require.Equal(t, snapshot[table], after[table], table)
			}
			require.Equal(t, 1, renameAuditCount(t, db, account.Subject.ID))
			_, err = runtime.FindAccount(t.Context(), goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: oldValue})
			require.ErrorIs(t, err, goauth.ErrAccountNotFound)
			if status == goauth.SubjectStatusActive {
				verified, err := runtime.VerifyCredential(t.Context(), goauth.Credential{
					Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: view.Identifier.DisplayValue}, Password: postgresRenamePassword,
				})
				require.NoError(t, err)
				require.Equal(t, account.Subject.ID, verified.Subject.ID)
			}
			replacement := provisionRenameIdentity(t, db, runtime, oldValue)
			require.NotEqual(t, account.Subject.ID, replacement.Subject.ID)
			var inherited int
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_subject_roles WHERE subject_id=$1`, replacement.Subject.ID).Scan(&inherited))
			require.Zero(t, inherited)
		})
	}
}

func TestPostgresLocalIdentityRenameCASNoopAndOverflow(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *sql.DB, *goauth.RenameLocalIdentityRequest)
		want   error
	}{
		{"missing-subject", func(_ *testing.T, _ *sql.DB, r *goauth.RenameLocalIdentityRequest) {
			r.SubjectID = goauth.NewSubjectID()
		}, goauth.ErrAccountNotFound},
		{"wrong-old", func(_ *testing.T, _ *sql.DB, r *goauth.RenameLocalIdentityRequest) {
			r.ExpectedIdentifier.Value = "wrong"
		}, goauth.ErrLocalIdentifierConflict},
		{"stale-version", func(_ *testing.T, _ *sql.DB, r *goauth.RenameLocalIdentityRequest) { r.ExpectedSecurityVersion++ }, goauth.ErrSecurityVersionMismatch},
		{"exact-noop", func(_ *testing.T, _ *sql.DB, r *goauth.RenameLocalIdentityRequest) {
			r.NewIdentifier = r.ExpectedIdentifier
		}, goauth.ErrIdentifierUnchanged},
		{"cas-before-noop", func(_ *testing.T, _ *sql.DB, r *goauth.RenameLocalIdentityRequest) {
			r.NewIdentifier = r.ExpectedIdentifier
			r.ExpectedSecurityVersion++
		}, goauth.ErrSecurityVersionMismatch},
		{"missing-primary", func(t *testing.T, db *sql.DB, r *goauth.RenameLocalIdentityRequest) {
			_, err := db.Exec(`UPDATE auth_identifiers SET is_primary=false WHERE subject_id=$1`, r.SubjectID)
			require.NoError(t, err)
		}, goauth.ErrLocalIdentifierConflict},
		{"missing-credential", func(t *testing.T, db *sql.DB, r *goauth.RenameLocalIdentityRequest) {
			_, err := db.Exec(`DELETE FROM auth_local_credentials WHERE subject_id=$1`, r.SubjectID)
			require.NoError(t, err)
		}, goauth.ErrAccountNotFound},
		{"version-overflow", func(t *testing.T, db *sql.DB, r *goauth.RenameLocalIdentityRequest) {
			r.ExpectedSecurityVersion = math.MaxInt64
			_, err := db.Exec(`UPDATE auth_subjects SET security_version=$2 WHERE id=$1`, r.SubjectID, r.ExpectedSecurityVersion)
			require.NoError(t, err)
		}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := renamePostgresRuntime(t, db, nil)
			account := provisionRenameIdentity(t, db, runtime, "CAS-Original")
			request := renameRequest(account, "CAS-Original", "CAS-Renamed")
			test.change(t, db, &request)
			before := renameIdentitySnapshot(t, db, account.Subject.ID)
			view, err := runtime.RenameLocalIdentity(t.Context(), request)
			require.Error(t, err)
			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			}
			require.Zero(t, view)
			require.Equal(t, before, renameIdentitySnapshot(t, db, account.Subject.ID))
		})
	}
}

func TestPostgresLocalIdentityRenameRejectsEveryAliasCollision(t *testing.T) {
	for _, targetKind := range []string{"other-primary", "other-secondary", "own-secondary"} {
		t.Run(targetKind, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := renamePostgresRuntime(t, db, nil)
			account := provisionRenameIdentity(t, db, runtime, "Collision-Original")
			target := account
			if targetKind != "own-secondary" {
				target = provisionRenameIdentity(t, db, runtime, "Collision-Target-Primary")
			}
			value := "Collision-Target-Primary"
			if targetKind != "other-primary" {
				value = "Reserved-Alias"
				insertRenameIdentifier(t, db, target.Subject.ID, postgresIdentityScheme, value, false)
			}
			before, targetBefore := renameIdentitySnapshot(t, db, account.Subject.ID), renameIdentitySnapshot(t, db, target.Subject.ID)
			view, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(account, "Collision-Original", value))
			require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
			require.Zero(t, view)
			require.Equal(t, before, renameIdentitySnapshot(t, db, account.Subject.ID))
			require.Equal(t, targetBefore, renameIdentitySnapshot(t, db, target.Subject.ID))
		})
	}
}

func TestPostgresLocalIdentityRenameCaseSensitiveAndNormalizedDisplayEdit(t *testing.T) {
	for _, fold := range []bool{false, true} {
		t.Run(map[bool]string{false: "case-sensitive", true: "normalized-display-edit"}[fold], func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := renamePostgresRuntime(t, db, func(config *goauth.Config) {
				if fold {
					config.IdentifierResolvers[postgresIdentityScheme] = goauth.IdentifierResolverFunc(func(_ context.Context, input goauth.IdentifierInput) (goauth.IdentifierInput, error) {
						input.Value = strings.ToLower(input.Value)
						return input, nil
					})
				}
			})
			account := provisionRenameIdentity(t, db, runtime, "MiXeD")
			request := renameRequest(account, "MiXeD", "MIXED")
			if fold {
				request.ExpectedIdentifier.Value = "mixed"
			}
			view, err := runtime.RenameLocalIdentity(t.Context(), request)
			require.NoError(t, err)
			require.Equal(t, "MIXED", view.Identifier.DisplayValue)
			want := "MIXED"
			if fold {
				want = "mixed"
			}
			require.Equal(t, want, view.Identifier.NormalizedValue)
			require.Equal(t, account.Subject.SecurityVersion+1, view.Account.Subject.SecurityVersion)
			require.Equal(t, account.Profile, view.Account.Profile)
			require.Zero(t, view.Account.PrimaryEmail)
			_, err = runtime.RenameLocalIdentity(t.Context(), request)
			require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
			_, err = runtime.RenameLocalIdentity(t.Context(), renameRequest(view.Account, "MIXED", "MIXED"))
			require.ErrorIs(t, err, goauth.ErrIdentifierUnchanged)
			require.Equal(t, 1, renameAuditCount(t, db, account.Subject.ID))
		})
	}
}

func TestPostgresLocalIdentityRenameStoreRejectsMalformedRequests(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	account := provisionRenameIdentity(t, db, runtime, "StoreOriginal")
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	base := goauth.RenameLocalIdentityStoreRequest{
		SubjectID: account.Subject.ID, Scheme: postgresIdentityScheme, ExpectedNormalizedValue: "StoreOriginal",
		ExpectedSecurityVersion: account.Subject.SecurityVersion, NewDisplayValue: "StoreRenamed",
		NewNormalizedValue: "StoreRenamed", Now: time.Now().UTC(),
	}
	before := renameIdentitySnapshot(t, db, account.Subject.ID)
	for _, field := range []string{"old", "display", "normalized"} {
		for _, invalid := range []string{"", "invalid\x00value", string([]byte{0xff}), strings.Repeat("x", 257)} {
			request := base
			switch field {
			case "old":
				request.ExpectedNormalizedValue = invalid
			case "display":
				request.NewDisplayValue = invalid
			case "normalized":
				request.NewNormalizedValue = invalid
			}
			view, err := store.RenameLocalIdentity(t.Context(), request)
			require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
			require.Zero(t, view)
			require.Equal(t, before, renameIdentitySnapshot(t, db, account.Subject.ID))
		}
	}
	for _, scheme := range []goauth.IdentifierScheme{"", goauth.IdentifierSchemeEmail, "UPPER", "with space"} {
		request := base
		request.Scheme = scheme
		view, err := store.RenameLocalIdentity(t.Context(), request)
		require.ErrorIs(t, err, goauth.ErrInvalidIdentifierScheme)
		require.Zero(t, view)
	}
	base.Now = time.Time{}
	view, err := store.RenameLocalIdentity(t.Context(), base)
	require.Error(t, err)
	require.Zero(t, view)
	require.Equal(t, before, renameIdentitySnapshot(t, db, account.Subject.ID))
}

func assertRenameIdentifierPersisted(t *testing.T, expected, actual goauth.Identifier) {
	t.Helper()
	// PostgreSQL timestamps have microsecond precision; compare all other
	// fields exactly, including the unchanged identifier creation timestamp.
	require.True(t, expected.UpdatedAt.Truncate(time.Microsecond).Equal(actual.UpdatedAt),
		"returned update time must equal the stored PostgreSQL microsecond value")
	expected.UpdatedAt = actual.UpdatedAt
	require.Equal(t, expected, actual)
}
