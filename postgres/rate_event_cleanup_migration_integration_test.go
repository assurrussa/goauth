//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

func TestRateEventCleanupMigrationUpgradesV6WithoutDataChanges(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	installPreRetirementSchema(t, db, 5)
	data, err := os.ReadFile("migrations/00005_subject_retirement.sql")
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), string(data))
	require.NoError(t, err)
	checksum := sha256.Sum256(data)
	_, err = db.ExecContext(t.Context(),
		`INSERT INTO goauth_migration_history(version,checksum) VALUES(6,$1)`, hex.EncodeToString(checksum[:]))
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `INSERT INTO goauth_schema_version(version) VALUES(6)`)
	require.NoError(t, err)
	seedPreRetirementSchema(t, db, 6)
	_, err = db.ExecContext(t.Context(), `UPDATE auth_subjects SET retired_at=updated_at WHERE status='disabled'`)
	require.NoError(t, err)
	before := retirementMigrationSnapshot(t, db, 6)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, postgres.VerifySchema(t.Context(), db))
	require.True(t, reflect.DeepEqual(before, retirementMigrationSnapshot(t, db, 6)),
		"schema7 must preserve every prior row/history")
	data, err = os.ReadFile("migrations/00006_rate_event_cleanup.sql")
	require.NoError(t, err)
	checksum = sha256.Sum256(data)
	var recorded string
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT checksum FROM goauth_migration_history WHERE version=7`).Scan(&recorded))
	require.Equal(t, hex.EncodeToString(checksum[:]), recorded)
	before = retirementMigrationSnapshot(t, db, 7)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.True(t, reflect.DeepEqual(before, retirementMigrationSnapshot(t, db, 7)), "repeat migration changed data/history")
}

func TestRateEventCleanupMigrationRejectsIndexDrift(t *testing.T) {
	for _, index := range []string{
		"", "(id,occurred_at)", "(occurred_at DESC,id)", "(occurred_at,id DESC)",
		"(occurred_at,id) WHERE subject_id IS NULL", "(occurred_at,id) INCLUDE (action)",
		"USING hash (occurred_at)", "(occurred_at)",
	} {
		t.Run(index, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			_, err := db.ExecContext(t.Context(), `DROP INDEX auth_rate_limit_events_retention_idx`)
			require.NoError(t, err)
			if index != "" {
				_, err = db.ExecContext(t.Context(), `CREATE INDEX auth_rate_limit_events_retention_idx ON auth_rate_limit_events `+index)
				require.NoError(t, err)
			}
			require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
			require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaNeedsMigration)
		})
	}
}

func TestRateEventCleanupMigrationRejectsChecksumAndFutureVersion(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	_, err := db.ExecContext(t.Context(), `UPDATE goauth_migration_history SET checksum='modified' WHERE version=7`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaChecksumMismatch)
	require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaChecksumMismatch)
	_, err = db.ExecContext(t.Context(), `INSERT INTO goauth_schema_version(version) VALUES(8)`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrFutureSchema)
	require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrFutureSchema)
}

func TestRateEventCleanupSchema6BinaryRefusesStartup(t *testing.T) {
	source := os.Getenv("GOAUTH_TEST_V6_SOURCE_DIR")
	if source == "" {
		t.Skip("GOAUTH_TEST_V6_SOURCE_DIR is not configured")
	}
	testRetirementOldBinary(t, source, "e5808d8d4b225e0d79701996b41d325bd0292811514748aab1ae1464732eda57")
}
