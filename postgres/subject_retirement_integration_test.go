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

func retirementRequest(account goauth.Account, login string) goauth.RetireLocalIdentityRequest {
	return goauth.RetireLocalIdentityRequest{
		SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
		ExpectedIdentifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: login},
	}
}

func retirementAuditCount(t *testing.T, db *sql.DB, id goauth.SubjectID) int {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_security_audit_events
 WHERE subject_id=$1 AND event_type=$2`, id, goauth.SecurityEventSubjectRetired).Scan(&count))
	return count
}

func TestPostgresSubjectRetirementPreservesOwnershipAndReleasesOnlySelectedLogin(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	var roleID int64
	require.NoError(t, db.QueryRowContext(t.Context(), `INSERT INTO auth_roles(public_id,slug,name)
 VALUES($1,'retirement-fixture-role','Retirement fixture') RETURNING id`, goauth.NewSubjectID()).Scan(&roleID))
	t.Cleanup(func() { _, err := db.Exec(`DELETE FROM auth_roles WHERE id=$1`, roleID); require.NoError(t, err) })
	for _, status := range []goauth.SubjectStatus{goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled} {
		t.Run(string(status), func(t *testing.T) {
			login := "Retire-" + string(status)
			account := provisionRenameIdentity(t, db, runtime, login)
			if status != goauth.SubjectStatusActive {
				_, err := runtime.SetSubjectStatus(t.Context(), account.Subject.ID, status)
				require.NoError(t, err)
			}
			id := account.Subject.ID
			insertRenameIdentifier(t, db, id, postgresIdentityScheme, login+"-alias", false)
			insertRenameIdentifier(t, db, id, "other_custom", login+"-other", true)
			email := strings.ToLower(login) + "@example.test"
			insertRenameIdentifier(t, db, id, goauth.IdentifierSchemeEmail, email, true)
			insertRenameIdentifier(t, db, id, goauth.IdentifierSchemeEmail, login+"-secondary@example.test", false)
			_, err := db.ExecContext(t.Context(), `UPDATE auth_identifiers SET verified_at=created_at
WHERE subject_id=$1 AND scheme='email' AND is_primary=true`, id)
			require.NoError(t, err)
			_, err = db.ExecContext(t.Context(), `INSERT INTO auth_subject_roles(subject_id,role_id) VALUES($1,$2)`, id, roleID)
			require.NoError(t, err)
			link := goauth.IdentityLink{
				ID: goauth.NewSubjectID().String(), SubjectID: id, Issuer: "https://retirement.example.test",
				ExternalSubject: login, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
			}
			_, err = store.LinkIdentity(t.Context(), link)
			require.NoError(t, err)
			before, err := runtime.GetSubjectLifecycle(t.Context(), id)
			require.NoError(t, err)
			require.Nil(t, before.RetiredAt)
			primary, err := runtime.GetLocalIdentifier(t.Context(), id, postgresIdentityScheme)
			require.NoError(t, err)
			snapshot := renameIdentitySnapshot(t, db, id)
			var reservedBefore string
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT jsonb_agg(to_jsonb(i) ORDER BY id)::text
FROM auth_identifiers i WHERE subject_id=$1 AND id<>$2`, id, primary.ID).Scan(&reservedBefore))
			view, err := runtime.RetireLocalIdentity(t.Context(), retirementRequest(before.Account, login))
			require.NoError(t, err)
			require.Equal(t, id, view.Account.Subject.ID)
			require.Equal(t, goauth.SubjectStatusDisabled, view.Account.Subject.Status)
			require.Equal(t, before.Account.Subject.SecurityVersion+1, view.Account.Subject.SecurityVersion)
			require.Equal(t, before.Account.Subject.CreatedAt, view.Account.Subject.CreatedAt)
			require.Equal(t, before.Account.Profile, view.Account.Profile)
			require.Equal(t, before.Account.PrimaryEmail, view.Account.PrimaryEmail)
			require.NotNil(t, view.RetiredAt)
			require.True(t, view.Account.Subject.UpdatedAt.Equal(*view.RetiredAt))
			read, err := runtime.GetSubjectLifecycle(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, view, read, "the returned marker and timestamps are persisted database values")
			after := renameIdentitySnapshot(t, db, id)
			for _, table := range []string{"auth_basic_profiles", "auth_identity_links", "auth_subject_roles"} {
				require.Equal(t, snapshot[table], after[table], table)
			}
			var count int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_identifiers WHERE subject_id=$1`, id).Scan(&count))
			require.Equal(t, 4, count)
			var reservedAfter string
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT jsonb_agg(to_jsonb(i) ORDER BY id)::text
FROM auth_identifiers i WHERE subject_id=$1`, id).Scan(&reservedAfter))
			require.Equal(t, reservedBefore, reservedAfter, "all retained identifier IDs and values remain exact")
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_identifiers WHERE id=$1`, primary.ID).Scan(&count))
			require.Zero(t, count)
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_local_credentials WHERE subject_id=$1`, id).Scan(&count))
			require.Zero(t, count)
			require.Equal(t, 1, retirementAuditCount(t, db, id))
			for _, next := range []goauth.SubjectStatus{goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled} {
				result, err := runtime.SetSubjectStatus(t.Context(), id, next)
				require.ErrorIs(t, err, goauth.ErrSubjectRetired)
				require.Zero(t, result)
			}
			_, err = runtime.RenameLocalIdentity(t.Context(), renameRequest(view.Account, login, "CannotRevive"))
			require.ErrorIs(t, err, goauth.ErrSubjectRetired)
			_, err = runtime.RetireLocalIdentity(t.Context(), retirementRequest(view.Account, login))
			require.ErrorIs(t, err, goauth.ErrSubjectRetired)
			_, err = store.LinkIdentity(t.Context(), goauth.IdentityLink{SubjectID: id, Issuer: link.Issuer, ExternalSubject: "new"})
			require.ErrorIs(t, err, goauth.ErrSubjectRetired)
			owned, storedLink, err := store.ResolveIdentityLink(t.Context(), link.Issuer, link.ExternalSubject)
			require.NoError(t, err)
			require.Equal(t, id, owned.Subject.ID)
			require.Equal(t, id, storedLink.SubjectID)
			require.Equal(t, goauth.SubjectStatusDisabled, owned.Subject.Status)
			_, err = runtime.ResolveExternalIdentity(t.Context(), goauth.ExternalIdentity{
				Issuer: link.Issuer, Subject: link.ExternalSubject,
			})
			require.ErrorIs(t, err, goauth.ErrAccountUnavailable)
			_, err = runtime.ResolveExternalIdentity(t.Context(), goauth.ExternalIdentity{
				Issuer: link.Issuer, Subject: "new-external-" + login, Email: email, EmailVerified: true,
			})
			require.ErrorIs(t, err, goauth.ErrAccountUnavailable, "retained verified email cannot auto-link to replacement")
			freshID := goauth.NewSubjectID()
			fresh := goauth.Account{Subject: goauth.Subject{
				ID: freshID, Status: goauth.SubjectStatusActive, SecurityVersion: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
			}, PrimaryEmail: goauth.Identifier{
				ID: goauth.NewSubjectID().String(), SubjectID: freshID,
				Scheme: goauth.IdentifierSchemeEmail, NormalizedValue: "fresh-retirement@example.test",
			}}
			_, _, err = store.CreateSSOAccount(t.Context(), goauth.SSOAccountRecord{
				Account: fresh,
				Link: goauth.IdentityLink{
					ID: goauth.NewSubjectID().String(), SubjectID: id,
					Issuer: link.Issuer, ExternalSubject: "misbound-" + login,
				},
			})
			require.Error(t, err, "SSO creation must not attach a misbound link to a tombstone")
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_subjects WHERE id=$1`, freshID).Scan(&count))
			require.Zero(t, count)
			replacement := provisionRenameIdentity(t, db, runtime, login)
			require.NotEqual(t, id, replacement.Subject.ID)
			for _, table := range []string{"auth_subject_roles", "auth_identity_links", "auth_sessions", "auth_refresh_families", "auth_oidc_refresh_families"} {
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table+` WHERE subject_id=$1`, replacement.Subject.ID).Scan(&count))
				require.Zero(t, count, table)
			}
			_, err = runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{Email: email, Password: postgresRenamePassword})
			require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists, "retained email ownership must prevent silent linking")
			_, err = runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
				Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: login + "-alias"},
				Password:   postgresRenamePassword,
			})
			require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists, "retained secondary alias remains reserved")
			attempted := before.Account
			attempted.PrimaryEmail = goauth.Identifier{}
			_, err = store.CreateLocalIdentity(t.Context(), goauth.LocalIdentityRecord{
				LocalAccountRecord: goauth.LocalAccountRecord{Account: attempted, PasswordPHC: "synthetic-phc"},
				Identifier: goauth.Identifier{
					ID: goauth.NewSubjectID().String(), SubjectID: id,
					Scheme: postgresIdentityScheme, DisplayValue: "AttemptRetiredUUID", NormalizedValue: "AttemptRetiredUUID",
				},
			})
			require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
			final, err := runtime.GetSubjectLifecycle(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, view, final)
		})
	}
}

func TestPostgresSubjectRetirementCASCredentialAndOverflow(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, *sql.DB, *goauth.RetireLocalIdentityRequest)
		want   error
	}{
		{"version", func(_ *testing.T, _ *sql.DB, r *goauth.RetireLocalIdentityRequest) { r.ExpectedSecurityVersion++ }, goauth.ErrSecurityVersionMismatch},
		{"login", func(_ *testing.T, _ *sql.DB, r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Value = "Wrong"
		}, goauth.ErrLocalIdentifierConflict},
		{"credential", func(t *testing.T, db *sql.DB, r *goauth.RetireLocalIdentityRequest) {
			t.Helper()
			_, err := db.Exec(`DELETE FROM auth_local_credentials WHERE subject_id=$1`, r.SubjectID)
			require.NoError(t, err)
		}, goauth.ErrAccountNotFound},
		{"primary", func(t *testing.T, db *sql.DB, r *goauth.RetireLocalIdentityRequest) {
			t.Helper()
			_, err := db.Exec(`UPDATE auth_identifiers SET is_primary=false WHERE subject_id=$1`, r.SubjectID)
			require.NoError(t, err)
		}, goauth.ErrLocalIdentifierConflict},
		{"overflow", func(t *testing.T, db *sql.DB, r *goauth.RetireLocalIdentityRequest) {
			t.Helper()
			r.ExpectedSecurityVersion = math.MaxInt64
			_, err := db.Exec(`UPDATE auth_subjects SET security_version=$2 WHERE id=$1`, r.SubjectID, int64(math.MaxInt64))
			require.NoError(t, err)
		}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := renamePostgresRuntime(t, db, nil)
			account := provisionRenameIdentity(t, db, runtime, "RetireCAS")
			request := retirementRequest(account, "RetireCAS")
			test.change(t, db, &request)
			before := renameIdentitySnapshot(t, db, account.Subject.ID)
			view, err := runtime.RetireLocalIdentity(t.Context(), request)
			require.Error(t, err)
			require.Zero(t, view)
			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			}
			require.Equal(t, before, renameIdentitySnapshot(t, db, account.Subject.ID))
		})
	}
}

func TestPostgresSubjectLifecycleRejectsForeignDatabaseContext(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	account := provisionRenameIdentity(t, db, runtime, "RetireForeign")
	foreign := renamePostgresRuntime(t, integrationDB(t), nil)
	require.NoError(t, foreign.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		view, err := runtime.GetSubjectLifecycle(ctx, account.Subject.ID)
		require.ErrorContains(t, err, "different database handle")
		require.Zero(t, view)
		view, err = runtime.RetireLocalIdentity(ctx, retirementRequest(account, "RetireForeign"))
		require.Error(t, err)
		require.Zero(t, view)
		return nil
	}))
}

var _ goauth.LocalIdentityRetirementStore = (*postgres.Store)(nil)
