package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
)

const (
	sessionOIDCSchemaVersion = 8
	sessionOIDCFamiliesTable = "auth_oidc_refresh_families"
	sessionOIDCRequestsTable = "auth_oidc_authorization_requests"
	sessionOIDCCodesTable    = "auth_oidc_authorization_codes"
)
const sessionOIDCMigration = "migrations/00007_session_oidc.sql"

func applySessionOIDCMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifyRateEventCleanupSchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(sessionOIDCMigration)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply session OIDC migration: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err = tx.ExecContext(ctx, `INSERT INTO goauth_migration_history(version,checksum) VALUES($1,$2)`,
		sessionOIDCSchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES($1)`, sessionOIDCSchemaVersion)
	return err
}

func verifySessionOIDCSchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(sessionOIDCMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	err = q.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version=$1`,
		sessionOIDCSchemaVersion).Scan(&recorded)
	if err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}

	for _, verify := range []func(context.Context, queryRower) error{
		verifySessionOIDCColumns, verifySessionOIDCConstraints, verifySessionOIDCGuards, verifySessionOIDCIndexes,
	} {
		if err := verify(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func verifySessionOIDCColumns(ctx context.Context, q queryRower) error {
	var err error
	// Verify every new column's exact type/nullability and the critical index and
	// trigger shape. Guard function bodies are compared byte-for-byte with this
	// checksummed migration, so a disabled or weakened replacement fails closed.
	var valid bool
	err = q.QueryRowContext(ctx, `WITH expected(table_name,column_name,type_name,required) AS (VALUES
 ('auth_oidc_refresh_families','session_id','text',false),
 ('auth_oidc_refresh_families','authorization_stamp','text',false),
 ('auth_oidc_refresh_families','absolute_expires_at','timestamptz',false),
 ('auth_oidc_authorization_requests','selector','text',true),
 ('auth_oidc_authorization_requests','key_id','text',true),
 ('auth_oidc_authorization_requests','secret_digest','bytea',true),
 ('auth_oidc_authorization_requests','client_id','text',true),
 ('auth_oidc_authorization_requests','client_revision','int8',true),
 ('auth_oidc_authorization_requests','redirect_uri','text',true),
 ('auth_oidc_authorization_requests','state','text',true),
 ('auth_oidc_authorization_requests','nonce','text',true),
 ('auth_oidc_authorization_requests','scopes','text',true),
 ('auth_oidc_authorization_requests','code_challenge','text',true),
 ('auth_oidc_authorization_requests','code_challenge_method','text',true),
 ('auth_oidc_authorization_requests','requested_at','timestamptz',true),
 ('auth_oidc_authorization_requests','expires_at','timestamptz',true),
 ('auth_oidc_authorization_requests','prompt','text',true),
 ('auth_oidc_authorization_requests','max_age_seconds','int8',false),
 ('auth_oidc_authorization_requests','browser_binding','text',true),
 ('auth_oidc_authorization_requests','login_session_id','text',false),
 ('auth_oidc_authorization_requests','login_cookie_digest','text',false),
 ('auth_oidc_authorization_requests','login_authenticated_at','timestamptz',false),
 ('auth_oidc_authorization_requests','consumed_at','timestamptz',false),
 ('auth_oidc_authorization_codes','selector','text',true),
 ('auth_oidc_authorization_codes','key_id','text',true),
 ('auth_oidc_authorization_codes','secret_digest','bytea',true),
 ('auth_oidc_authorization_codes','subject_id','uuid',true),
 ('auth_oidc_authorization_codes','security_version','int8',true),
 ('auth_oidc_authorization_codes','client_id','text',true),
 ('auth_oidc_authorization_codes','redirect_uri','text',true),
 ('auth_oidc_authorization_codes','scopes','text',true),
 ('auth_oidc_authorization_codes','nonce','text',true),
 ('auth_oidc_authorization_codes','code_challenge','text',true),
 ('auth_oidc_authorization_codes','code_challenge_method','text',true),
 ('auth_oidc_authorization_codes','authenticated_at','timestamptz',true),
 ('auth_oidc_authorization_codes','created_at','timestamptz',true),
 ('auth_oidc_authorization_codes','expires_at','timestamptz',true),
 ('auth_oidc_authorization_codes','session_id','text',true),
 ('auth_oidc_authorization_codes','authorization_stamp','text',true),
 ('auth_oidc_authorization_codes','absolute_expires_at','timestamptz',true),
 ('auth_oidc_authorization_codes','consumed_at','timestamptz',false),
 ('auth_oidc_authorization_codes','family_id','uuid',false))
 SELECT NOT EXISTS(SELECT 1 FROM expected e WHERE NOT EXISTS(
 SELECT 1 FROM pg_attribute a JOIN pg_type ty ON ty.oid=a.atttypid
 WHERE a.attrelid=to_regclass('public.'||e.table_name) AND a.attname=e.column_name
 AND NOT a.attisdropped AND ty.typname=e.type_name AND a.attnotnull=e.required
 AND NOT EXISTS(SELECT 1 FROM pg_constraint n WHERE n.conrelid=a.attrelid AND n.contype='n'
 AND a.attnum=ANY(n.conkey) AND (NOT n.convalidated OR (to_jsonb(n)->>'conenforced')::boolean=false))))`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}

func verifySessionOIDCConstraints(ctx context.Context, q queryRower) error {
	var err error
	var valid bool
	for _, constraint := range []struct{ table, name string }{
		{sessionOIDCFamiliesTable, "auth_oidc_family_binding_check"},
		{sessionOIDCRequestsTable, "auth_oidc_request_completion_check"},
		{sessionOIDCCodesTable, "auth_oidc_code_expiry_check"},
		{sessionOIDCCodesTable, "auth_oidc_code_family_check"},
	} {
		err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint c
  WHERE c.conrelid=to_regclass('public.'||$1) AND c.conname=$2 AND c.contype='c'
  AND c.convalidated AND NOT c.connoinherit
  AND (to_jsonb(c)->>'conenforced')::boolean IS DISTINCT FROM false)`, constraint.table, constraint.name).Scan(&valid)
		if err != nil {
			return err
		}
		if !valid {
			return ErrSchemaNeedsMigration
		}
	}
	err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint c
 WHERE c.conrelid=to_regclass('public.auth_oidc_authorization_codes')
 AND c.confrelid=to_regclass('public.auth_oidc_refresh_families') AND c.contype='f'
 AND c.convalidated AND c.confdeltype='c' AND c.confupdtype='a' AND NOT c.condeferrable
 AND pg_get_constraintdef(c.oid)=$1)`,
		"FOREIGN KEY (family_id) REFERENCES auth_oidc_refresh_families(id) ON DELETE CASCADE").Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	for _, table := range []string{sessionOIDCRequestsTable, sessionOIDCCodesTable} {
		err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass('public.'||$1)
  AND i.indisprimary AND i.indisvalid AND i.indisready AND i.indislive AND i.indnatts=1
  AND pg_get_indexdef(i.indexrelid,1,true)='selector')`, table).Scan(&valid)
		if err != nil {
			return err
		}
		if !valid {
			return ErrSchemaNeedsMigration
		}
	}
	return nil
}

func verifySessionOIDCGuards(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(sessionOIDCMigration)
	if err != nil {
		return err
	}
	var valid bool
	guards := []struct{ name, table string }{
		{"auth_oidc_family_guard", sessionOIDCFamiliesTable},
		{"auth_oidc_token_guard", "auth_oidc_refresh_tokens"},
		{"auth_oidc_request_guard", sessionOIDCRequestsTable},
		{"auth_oidc_code_guard", sessionOIDCCodesTable},
	}
	for _, guard := range guards {
		pattern := regexp.MustCompile(`(?s)CREATE FUNCTION ` + guard.name + `\(\).*?AS \$guard\$(.*?)\$guard\$;`)
		body := pattern.FindSubmatch(data)
		if len(body) != 2 {
			return fmt.Errorf("missing embedded OIDC guard %s", guard.name)
		}
		err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
  JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE t.tgrelid=to_regclass('public.'||$1) AND t.tgname=$2 AND t.tgenabled='O' AND t.tgtype=23
  AND NOT t.tgisinternal AND t.tgqual IS NULL AND t.tgnargs=0 AND t.tgattr=''::int2vector
  AND p.proname=$2 AND n.nspname='public' AND p.pronargs=0 AND NOT p.prosecdef
  AND p.prorettype='trigger'::regtype AND p.provolatile='v'
  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
  AND p.prosrc=$3 AND p.proconfig=ARRAY['search_path=pg_catalog, public'])`,
			guard.table, guard.name, string(body[1])).Scan(&valid)
		if err != nil {
			return err
		}
		if !valid {
			return ErrSchemaNeedsMigration
		}
	}
	return nil
}

func verifySessionOIDCIndexes(ctx context.Context, q queryRower) error {
	var err error
	var valid bool
	for _, index := range []struct{ name, table, tail string }{
		{"auth_oidc_requests_expiry_idx", sessionOIDCRequestsTable, "selector"},
		{"auth_oidc_codes_expiry_idx", sessionOIDCCodesTable, "selector"},
		{"auth_oidc_families_expiry_idx", sessionOIDCFamiliesTable, "id"},
	} {
		err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
  JOIN pg_am a ON a.oid=c.relam WHERE i.indrelid=to_regclass('public.'||$1) AND c.relname=$2 AND a.amname='btree'
  AND i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique AND i.indnatts=2 AND i.indnkeyatts=2
  AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indoption[0]=0 AND i.indoption[1]=0
  AND pg_get_indexdef(i.indexrelid,1,true)='expires_at' AND pg_get_indexdef(i.indexrelid,2,true)=$3)`,
			index.table, index.name, index.tail).Scan(&valid)
		if err != nil {
			return err
		}
		if !valid {
			return ErrSchemaNeedsMigration
		}
	}

	err = q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
 JOIN pg_am a ON a.oid=c.relam WHERE i.indrelid='public.auth_oidc_refresh_tokens'::regclass
 AND c.relname='auth_oidc_tokens_successor_idx' AND a.amname='btree'
 AND i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
 AND i.indnatts=1 AND i.indnkeyatts=1 AND i.indexprs IS NULL AND i.indoption[0]=0
 AND pg_get_indexdef(i.indexrelid,1,true)='replaced_by_selector'
 AND pg_get_expr(i.indpred,i.indrelid)='(replaced_by_selector IS NOT NULL)')`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
