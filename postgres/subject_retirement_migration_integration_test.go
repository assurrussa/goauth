//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

func TestSubjectRetirementMigrationUpgradesAllPublishedSchemas(t *testing.T) {
	for _, version := range []int{0, 2, 3, 4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			if version != 0 {
				installPreRetirementSchema(t, db, version)
				seedPreRetirementSchema(t, db, version)
				require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
			}
			var before map[string]string
			if version != 0 {
				before = retirementMigrationSnapshot(t, db, version)
			}
			require.NoError(t, postgres.Migrate(t.Context(), db))
			require.NoError(t, postgres.VerifySchema(t.Context(), db))
			var gotVersion int
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT max(version) FROM goauth_schema_version`).Scan(&gotVersion))
			require.Equal(t, 6, gotVersion)
			if version != 0 {
				require.Equal(t, before, retirementMigrationSnapshot(t, db, version), "upgrade must preserve preexisting data")
				var retired int
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT count(*) FROM auth_subjects WHERE retired_at IS NOT NULL`).Scan(&retired))
				require.Zero(t, retired, "existing disabled subjects must remain reversible")
			}
			first := retirementMigrationSnapshot(t, db, 6)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			require.Equal(t, first, retirementMigrationSnapshot(t, db, 6), "repeat migration must not rewrite rows or history")
			for schema, file := range map[int]string{
				3: "00002_notifications.sql", 4: "00003_local_identity.sql", 5: "00004_notification_expiry.sql", 6: "00005_subject_retirement.sql",
			} {
				data, err := os.ReadFile("migrations/" + file)
				require.NoError(t, err)
				checksum := sha256.Sum256(data)
				var recorded string
				require.NoError(t, db.QueryRowContext(t.Context(),
					`SELECT checksum FROM goauth_migration_history WHERE version=$1`, schema).Scan(&recorded))
				require.Equal(t, hex.EncodeToString(checksum[:]), recorded)
			}
		})
	}
}

func installPreRetirementSchema(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	files := []string{"00001_v0_2_baseline.sql", "00002_notifications.sql", "00003_local_identity.sql", "00004_notification_expiry.sql"}
	for i, file := range files {
		migrationVersion := i + 2
		if migrationVersion > version {
			break
		}
		data, err := os.ReadFile("migrations/" + file)
		require.NoError(t, err)
		_, err = db.ExecContext(t.Context(), string(data))
		require.NoError(t, err)
		if migrationVersion > 2 {
			checksum := sha256.Sum256(data)
			_, err = db.ExecContext(t.Context(), `INSERT INTO goauth_migration_history (version, checksum) VALUES ($1,$2)`,
				migrationVersion, hex.EncodeToString(checksum[:]))
			require.NoError(t, err)
			_, err = db.ExecContext(t.Context(), `INSERT INTO goauth_schema_version (version) VALUES ($1)`, migrationVersion)
			require.NoError(t, err)
		}
	}
}

func seedPreRetirementSchema(t *testing.T, db *sql.DB, version int) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
INSERT INTO auth_subjects (id,status,security_version,created_at,updated_at) VALUES
('00000000-0000-4000-8000-000000000001','active',9,'2026-01-01 00:00:00+00','2026-01-02 00:00:00+00'),
('00000000-0000-4000-8000-000000000002','suspended',10,'2026-01-01 00:00:00+00','2026-01-02 00:00:00+00'),
('00000000-0000-4000-8000-000000000003','disabled',11,'2026-01-01 00:00:00+00','2026-01-02 00:00:00+00');
INSERT INTO auth_identifiers (id,subject_id,scheme,display_value,normalized_value,is_primary,created_at,updated_at)
SELECT id,id,'hub_login',status,status,true,created_at,updated_at FROM auth_subjects;
INSERT INTO auth_local_credentials (subject_id,password_phc,created_at,updated_at)
SELECT id,'$argon2id$retirement-upgrade-fixture',created_at,updated_at FROM auth_subjects;
INSERT INTO auth_basic_profiles (subject_id,username,display_name,created_at,updated_at)
SELECT id,status,'Retained profile',created_at,updated_at FROM auth_subjects;
INSERT INTO auth_sessions (id,subject_id,realm,scope,security_version,created_at,expires_at,revoked_at)
SELECT id,id,'user','authenticated',security_version,created_at,'2027-01-01 00:00:00+00',updated_at FROM auth_subjects;
INSERT INTO auth_refresh_families (id,session_id,subject_id,realm,security_version,created_at,revoked_at,replayed_at)
SELECT id,id,id,'user',security_version,created_at,updated_at,updated_at FROM auth_subjects;
INSERT INTO auth_refresh_tokens (selector,family_id,key_id,secret_digest,created_at,expires_at,consumed_at)
SELECT status,id,'fixture',decode(repeat('00',32),'hex'),created_at,'2027-01-01 00:00:00+00',updated_at FROM auth_subjects;
INSERT INTO auth_oidc_refresh_families
(id,subject_id,client_id,scopes,security_version,authenticated_at,created_at,expires_at,revoked_at)
SELECT id,id,'client','openid',security_version,created_at,created_at,'2027-01-01 00:00:00+00',updated_at FROM auth_subjects;
INSERT INTO auth_oidc_refresh_tokens (selector,family_id,key_id,secret_digest,created_at,expires_at,consumed_at)
SELECT status,id,'fixture',decode(repeat('00',32),'hex'),created_at,'2027-01-01 00:00:00+00',updated_at FROM auth_subjects;
INSERT INTO auth_identity_links (id,subject_id,issuer,external_subject,created_at,updated_at)
SELECT id,id,'https://issuer.example.test',status,created_at,updated_at FROM auth_subjects;
INSERT INTO auth_password_reset_records (selector,subject_id,key_id,secret_digest,created_at,expires_at,consumed_at)
SELECT status,id,'fixture',decode(repeat('00',32),'hex'),created_at,'2027-01-01 00:00:00+00',updated_at FROM auth_subjects;
INSERT INTO auth_email_challenges (id,subject_id,identifier_id,purpose,key_id,code_digest,max_attempts,created_at,expires_at)
SELECT id,id,id,'confirmation','fixture',decode(repeat('00',32),'hex'),5,created_at,'2027-01-01 00:00:00+00' FROM auth_subjects;
INSERT INTO auth_email_change_records
(id,subject_id,new_display_value,new_normalized_value,key_id,code_digest,max_attempts,created_at,expires_at)
SELECT id,id,status || '@example.test',status || '@example.test','fixture',decode(repeat('00',32),'hex'),
5,created_at,'2027-01-01 00:00:00+00'
FROM auth_subjects;
INSERT INTO auth_security_audit_events (id,subject_id,event_type,attributes,occurred_at)
SELECT id,id,'fixture.retained','{"retained":true}',created_at FROM auth_subjects;
INSERT INTO auth_roles (id,public_id,slug,name) VALUES (1,'00000000-0000-4000-8000-000000000001','retained','Retained');
INSERT INTO auth_permissions (id,public_id,permission_key) VALUES (1,'00000000-0000-4000-8000-000000000001','retained:read');
INSERT INTO auth_role_permissions (role_id,permission_id) VALUES (1,1);
INSERT INTO auth_subject_roles (subject_id,role_id) SELECT id,1 FROM auth_subjects;
INSERT INTO auth_rate_limit_events (subject_id,key_id,bucket_digest,action,occurred_at)
SELECT id,'fixture',decode(repeat('00',32),'hex'),'fixture.retained',created_at FROM auth_subjects;`)
	require.NoError(t, err)
	if version >= 3 {
		_, err = db.ExecContext(t.Context(), `
INSERT INTO auth_notification_deliveries (id,subject_id,event_type,valid_until,key_id,nonce,ciphertext,additional_data,
created_at,delete_after,state,next_attempt_at)
SELECT id,id,'fixture.retained','2027-01-01 00:00:00+00','fixture','\x01','\x02','\x03',
created_at,'2027-01-01 00:00:00+00','blocked',created_at
FROM auth_subjects;`)
		require.NoError(t, err)
	}
	if version >= 4 {
		_, err = db.ExecContext(t.Context(), `UPDATE auth_local_credentials SET password_input_policy='legacy_bytes_256'`)
		require.NoError(t, err)
	}
}

func retirementMigrationSnapshot(t *testing.T, db *sql.DB, version int) map[string]string {
	t.Helper()
	tables := []string{
		"auth_subjects", "auth_identifiers", "auth_basic_profiles", "auth_local_credentials", "auth_sessions",
		"auth_refresh_families", "auth_refresh_tokens", "auth_oidc_refresh_families", "auth_oidc_refresh_tokens",
		"auth_password_reset_records", "auth_email_challenges", "auth_email_change_records", "auth_identity_links",
		"auth_roles", "auth_permissions", "auth_role_permissions", "auth_subject_roles", "auth_rate_limit_events",
		"auth_security_audit_events", "goauth_schema_version",
	}
	if version >= 3 {
		tables = append(tables, "auth_notification_deliveries", "goauth_migration_history")
	}
	result := make(map[string]string, len(tables))
	for _, table := range tables {
		expression, filter := "to_jsonb(r)", ""
		if table == "auth_subjects" && version < 6 {
			expression += " - 'retired_at'"
		}
		if table == "auth_local_credentials" && version < 4 {
			expression += " - 'password_input_policy'"
		}
		if table == "goauth_schema_version" || table == "goauth_migration_history" {
			filter = fmt.Sprintf(" WHERE version <= %d", version)
		}
		query := `SELECT COALESCE(jsonb_agg(data ORDER BY data::text),'[]'::jsonb)::text FROM (SELECT ` +
			expression + " AS data FROM " + table + " r" + filter + ") snapshots"
		var snapshot string
		require.NoError(t, db.QueryRowContext(t.Context(), query).Scan(&snapshot), table)
		result[table] = snapshot
	}
	return result
}

func TestSubjectRetirementMigrationRejectsCorruptFence(t *testing.T) {
	for _, test := range []struct {
		name, sql string
	}{
		{"missing marker", `ALTER TABLE auth_subjects DROP COLUMN retired_at`},
		{"wrong marker type", `ALTER TABLE auth_subjects ALTER COLUMN retired_at TYPE timestamp`},
		{"nonnullable marker", `ALTER TABLE auth_subjects ALTER COLUMN retired_at SET NOT NULL`},
		{"nullable status", `ALTER TABLE auth_subjects ALTER COLUMN status DROP NOT NULL`},
		{"missing check", `ALTER TABLE auth_subjects DROP CONSTRAINT auth_subjects_retirement_status_check`},
		{"same name permissive check", `ALTER TABLE auth_subjects DROP CONSTRAINT auth_subjects_retirement_status_check;
ALTER TABLE auth_subjects ADD CONSTRAINT auth_subjects_retirement_status_check CHECK (true)`},
		{"same name weakened check", `ALTER TABLE auth_subjects DROP CONSTRAINT auth_subjects_retirement_status_check;
ALTER TABLE auth_subjects ADD CONSTRAINT auth_subjects_retirement_status_check
CHECK (retired_at IS NULL OR status IN ('disabled','suspended'))`},
		{"not validated", `ALTER TABLE auth_subjects DROP CONSTRAINT auth_subjects_retirement_status_check;
ALTER TABLE auth_subjects ADD CONSTRAINT auth_subjects_retirement_status_check
CHECK (retired_at IS NULL OR status='disabled') NOT VALID`},
		{"equivalent rewritten check", `ALTER TABLE auth_subjects DROP CONSTRAINT auth_subjects_retirement_status_check;
ALTER TABLE auth_subjects ADD CONSTRAINT auth_subjects_retirement_status_check
CHECK (status='disabled' OR retired_at IS NULL)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			_, err := db.ExecContext(t.Context(), test.sql)
			require.NoError(t, err)
			require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
			require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaNeedsMigration)
			for _, autoMigrate := range []bool{false, true} {
				_, err := postgres.NewRuntime(postgres.Config{
					DB: db, AutoMigrate: autoMigrate,
					Runtime: runtimeConfig(t), NotificationSender: integrationNotificationSender(),
				})
				require.ErrorIs(t, err, postgres.ErrSchemaNeedsMigration)
			}
		})
	}
}

func TestSubjectRetirementMigrationRejectsNonEnforcedFence(t *testing.T) {
	db := integrationDB(t)
	var version int
	require.NoError(t, db.QueryRowContext(t.Context(), `SHOW server_version_num`).Scan(&version))
	if version < 180000 {
		t.Skip("NOT ENFORCED check constraints require PostgreSQL 18")
	}
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	_, err := db.ExecContext(t.Context(), `ALTER TABLE auth_subjects
DROP CONSTRAINT auth_subjects_retirement_status_check;
ALTER TABLE auth_subjects ADD CONSTRAINT auth_subjects_retirement_status_check
CHECK (retired_at IS NULL OR status='disabled') NOT ENFORCED`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
	require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaNeedsMigration)
}

func TestSubjectRetirementMigrationRejectsUnvalidatedStatusNullability(t *testing.T) {
	db := integrationDB(t)
	var version int
	require.NoError(t, db.QueryRowContext(t.Context(), `SHOW server_version_num`).Scan(&version))
	if version < 180000 {
		t.Skip("NOT VALID not-null constraints require PostgreSQL 18")
	}
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	_, err := db.ExecContext(t.Context(), `ALTER TABLE auth_subjects ALTER COLUMN status DROP NOT NULL;
INSERT INTO auth_subjects (id,status,security_version,created_at,updated_at,retired_at)
VALUES ('00000000-0000-4000-8000-000000000003',NULL,1,now(),now(),now());
ALTER TABLE auth_subjects ADD CONSTRAINT auth_subjects_status_not_null NOT NULL status NOT VALID`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
	require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaNeedsMigration)
}

func TestSubjectRetirementMigrationRejectsChecksumAndFutureSchema(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	_, err := db.ExecContext(t.Context(), `UPDATE goauth_migration_history SET checksum='changed' WHERE version=6`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaChecksumMismatch)
	require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaChecksumMismatch)
	_, err = db.ExecContext(t.Context(), `INSERT INTO goauth_schema_version (version) VALUES (7)`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrFutureSchema)
	require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrFutureSchema)
}

func TestSubjectRetirementFenceRollsBackOldStatusSQL(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	installPreRetirementSchema(t, db, 4)
	seedPreRetirementSchema(t, db, 4)
	// Prepare the unchanged v4 UPDATE before migration, like an already-running
	// binary with a cached SQL statement. PostgreSQL must enforce the new fence
	// even when that existing statement is reused after retirement.
	oldStatusUpdate, err := db.PrepareContext(t.Context(), `UPDATE auth_subjects
SET status = $2, security_version = security_version + 1, updated_at = $3
WHERE id = $1
RETURNING id, status, security_version, created_at, updated_at`)
	require.NoError(t, err)
	defer func() { _ = oldStatusUpdate.Close() }()
	require.NoError(t, postgres.Migrate(t.Context(), db))
	const subjectID = "00000000-0000-4000-8000-000000000003"
	_, err = db.ExecContext(t.Context(), `UPDATE auth_subjects SET retired_at=updated_at WHERE id=$1`, subjectID)
	require.NoError(t, err)
	before := retirementMigrationSnapshot(t, db, 6)
	for _, status := range []string{"active", "suspended"} {
		t.Run(status, func(t *testing.T) {
			tx, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			_, err = tx.ExecContext(t.Context(),
				`UPDATE auth_basic_profiles SET display_name='must roll back' WHERE subject_id=$1`, subjectID)
			require.NoError(t, err)
			var storedStatus string
			require.NoError(t, tx.QueryRowContext(t.Context(),
				`SELECT status FROM auth_subjects WHERE id=$1 FOR UPDATE`, subjectID).Scan(&storedStatus))
			require.Equal(t, "disabled", storedStatus)
			// The v4 setter does not know retired_at. Its unchanged UPDATE must
			// fail in PostgreSQL before any status/version/timestamp can commit.
			prepared := tx.StmtContext(t.Context(), oldStatusUpdate)
			defer func() { _ = prepared.Close() }()
			_, err = prepared.ExecContext(t.Context(), subjectID, status, time.Now().UTC())
			var constraintError *pgconn.PgError
			require.ErrorAs(t, err, &constraintError)
			require.Equal(t, "23514", constraintError.Code)
			require.Equal(t, "auth_subjects_retirement_status_check", constraintError.ConstraintName)
			require.NoError(t, tx.Rollback())
			require.Equal(t, before, retirementMigrationSnapshot(t, db, 6))
		})
	}
	// A nonretired disabled subject keeps the existing reversible semantics.
	_, err = db.ExecContext(t.Context(), `UPDATE auth_subjects SET status='disabled' WHERE status='active'`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `UPDATE auth_subjects SET status='active',security_version=security_version+1
WHERE id='00000000-0000-4000-8000-000000000001'`)
	require.NoError(t, err)
}

func TestSubjectRetirementMigrationFailureRollsBackVersionAndMarker(t *testing.T) {
	for _, version := range []int{4, 5} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) { testRetirementMigrationFailure(t, version) })
	}
}

func testRetirementMigrationFailure(t *testing.T, version int) {
	t.Helper()
	db := integrationDB(t)
	resetSchema(t, db)
	installPreRetirementSchema(t, db, version)
	seedPreRetirementSchema(t, db, version)
	before := retirementMigrationSnapshot(t, db, version)
	_, err := db.ExecContext(t.Context(), `ALTER TABLE auth_subjects
ADD CONSTRAINT auth_subjects_retirement_status_check CHECK (true)`)
	require.NoError(t, err)
	require.Error(t, postgres.Migrate(t.Context(), db))
	require.Equal(t, before, retirementMigrationSnapshot(t, db, version))
	var columns int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM information_schema.columns
WHERE table_schema='public' AND table_name='auth_subjects' AND column_name='retired_at'`).Scan(&columns))
	require.Zero(t, columns)
	_, err = db.ExecContext(t.Context(), `ALTER TABLE auth_subjects DROP CONSTRAINT auth_subjects_retirement_status_check`)
	require.NoError(t, err)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	require.NoError(t, postgres.VerifySchema(t.Context(), db))
}
