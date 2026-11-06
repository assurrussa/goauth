//go:build integration

package postgres_test

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

func removeSessionStepUpFixtureSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	data, err := os.ReadFile("migrations/00007_session_oidc.sql")
	require.NoError(t, err)
	original := string(data)
	begin := strings.Index(original, "CREATE FUNCTION auth_oidc_request_guard()")
	end := strings.Index(original[begin:], "$guard$;") + begin + len("$guard$;")
	_, err = db.Exec(`ALTER TABLE auth_oidc_authorization_requests DROP CONSTRAINT auth_oidc_request_step_up_check,
 DROP COLUMN interaction,DROP COLUMN step_up_session,DROP COLUMN step_up_binding,DROP COLUMN step_up_session_id,
 DROP COLUMN step_up_cookie_digest,DROP COLUMN step_up_verified_at;
 DELETE FROM goauth_schema_version WHERE version=16; DELETE FROM goauth_migration_history WHERE version=16;` +
		strings.Replace(original[begin:end], "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1))
	require.NoError(t, err)
}

func TestSessionStepUpMigrationPreservesSchema15Requests(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	removeSessionStepUpFixtureSchema(t, db)
	_, err := db.Exec(`INSERT INTO auth_oidc_authorization_requests(selector,key_id,secret_digest,client_id,client_revision,
 redirect_uri,state,nonce,scopes,code_challenge,code_challenge_method,requested_at,expires_at,prompt,browser_binding)
 VALUES('legacy','synthetic',decode(repeat('00',32),'hex'),'client',1,'https://client.example/callback','','','openid',
 'challenge','S256',now(),now()+interval '10 minutes','login','browser')`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, postgres.VerifySchema(t.Context(), db))
	var interaction string
	var missing bool
	require.NoError(t, db.QueryRow(`SELECT interaction,step_up_session IS NULL AND step_up_binding IS NULL AND step_up_session_id IS NULL FROM auth_oidc_authorization_requests WHERE selector='legacy'`).Scan(&interaction, &missing))
	require.Empty(t, interaction)
	require.True(t, missing)
}

func TestSessionStepUpSchemaRejectsTampering(t *testing.T) {
	for _, change := range []string{
		`ALTER TABLE auth_oidc_authorization_requests DROP COLUMN step_up_verified_at`,
		`ALTER TABLE auth_oidc_authorization_requests DROP CONSTRAINT auth_oidc_request_step_up_check`,
		`ALTER TABLE auth_oidc_authorization_requests DROP CONSTRAINT auth_oidc_request_step_up_check, ADD CONSTRAINT auth_oidc_request_step_up_check CHECK(true)`,
		`ALTER TABLE auth_oidc_authorization_requests DISABLE TRIGGER auth_oidc_request_guard`,
		`UPDATE goauth_migration_history SET checksum='tampered' WHERE version=16`,
	} {
		t.Run(change, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			_, err := db.Exec(change)
			require.NoError(t, err)
			require.Error(t, postgres.VerifySchema(t.Context(), db))
			require.Error(t, postgres.Migrate(t.Context(), db))
		})
	}
}
