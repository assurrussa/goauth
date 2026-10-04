//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

// Existing upgrade tests deliberately reconstruct older schemas. Remove only
// this additive fixture layer before they remove their own later columns.
func removeSessionOIDCSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`DROP TABLE auth_oidc_authorization_codes;
 DROP TABLE auth_oidc_authorization_requests;
 DROP TRIGGER auth_oidc_token_guard ON auth_oidc_refresh_tokens;
 DROP INDEX auth_oidc_tokens_successor_idx;
 DROP INDEX auth_oidc_families_expiry_idx;
 DROP TRIGGER auth_oidc_family_guard ON auth_oidc_refresh_families;
 DROP FUNCTION auth_oidc_code_guard(); DROP FUNCTION auth_oidc_request_guard();
 DROP FUNCTION auth_oidc_token_guard(); DROP FUNCTION auth_oidc_family_guard();
 ALTER TABLE auth_oidc_refresh_families DROP COLUMN session_id,DROP COLUMN authorization_stamp,DROP COLUMN absolute_expires_at;
 DELETE FROM goauth_migration_history WHERE version=8;
 DELETE FROM goauth_schema_version WHERE version=8`)
	require.NoError(t, err)
}

func TestSessionOIDCMigrationUpgradesSchema7(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	installPreRetirementSchema(t, db, 5)
	for i, name := range []string{"00005_subject_retirement.sql", "00006_rate_event_cleanup.sql"} {
		data, err := os.ReadFile("migrations/" + name)
		require.NoError(t, err)
		_, err = db.Exec(string(data))
		require.NoError(t, err)
		checksum := sha256.Sum256(data)
		_, err = db.Exec(`INSERT INTO goauth_migration_history(version,checksum) VALUES($1,$2)`, i+6, hex.EncodeToString(checksum[:]))
		require.NoError(t, err)
		_, err = db.Exec(`INSERT INTO goauth_schema_version(version) VALUES($1)`, i+6)
		require.NoError(t, err)
	}
	seedPreRetirementSchema(t, db, 7)
	before := retirementMigrationSnapshot(t, db, 7)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.True(t, reflect.DeepEqual(before, retirementMigrationSnapshot(t, db, 7)), "schema8 changed existing row values")
	require.NoError(t, postgres.VerifySchema(t.Context(), db))
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, postgres.Down(t.Context(), db, postgres.ConfirmResetAuthState))
	require.NoError(t, postgres.Migrate(t.Context(), db))
}

func TestSessionOIDCSchemaRejectsPartialOrWeakenedState(t *testing.T) {
	for _, change := range []string{
		`ALTER TABLE auth_oidc_authorization_requests DROP COLUMN login_cookie_digest`,
		`ALTER TABLE auth_oidc_authorization_requests ALTER COLUMN client_revision DROP NOT NULL`,
		`ALTER TABLE auth_oidc_refresh_families DISABLE TRIGGER auth_oidc_family_guard`,
		`ALTER TABLE auth_oidc_refresh_tokens DISABLE TRIGGER auth_oidc_token_guard`,
		`DROP INDEX auth_oidc_requests_expiry_idx`,
		`DROP INDEX auth_oidc_tokens_successor_idx`,
		`DROP INDEX auth_oidc_families_expiry_idx`,
		`ALTER TABLE auth_oidc_authorization_codes DROP CONSTRAINT auth_oidc_code_family_check`,
		`ALTER TABLE auth_oidc_authorization_codes DROP CONSTRAINT auth_oidc_authorization_codes_family_id_fkey`,
		`CREATE OR REPLACE FUNCTION auth_oidc_request_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$ BEGIN RETURN NEW; END $$`,
	} {
		t.Run(change, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			_, err := db.Exec(change)
			require.NoError(t, err)
			require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
			require.ErrorIs(t, postgres.Migrate(t.Context(), db), postgres.ErrSchemaNeedsMigration)
		})
	}
}
