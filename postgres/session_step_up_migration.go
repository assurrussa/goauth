package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed session_step_up_constraint.txt
var sessionStepUpConstraint string

const sessionStepUpMigration = "migrations/00015_session_step_up.sql"

func applySessionStepUpMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifySessionOIDCSchema(ctx, tx); err != nil {
		return err
	}
	if err := verifyNotificationGatewaySchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(sessionStepUpMigration)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, string(data)); err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	if _, err = tx.ExecContext(ctx, `INSERT INTO goauth_migration_history(version,checksum) VALUES(16,$1)`,
		hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES(16)`)
	return err
}

func verifySessionStepUpSchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(sessionStepUpMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err = q.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version=16`).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	if err = q.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='auth_oidc_authorization_requests'::regclass
 AND conname='auth_oidc_request_step_up_check' AND contype='c' AND convalidated
 AND NOT connoinherit AND pg_get_constraintdef(oid)=$1
 AND (to_jsonb(pg_constraint)->>'conenforced')::boolean IS DISTINCT FROM false)
 AND (SELECT count(*)=6 FROM information_schema.columns WHERE table_schema='public'
 AND table_name='auth_oidc_authorization_requests' AND
 ((column_name='interaction' AND udt_name='text' AND is_nullable='NO' AND column_default='''''::text') OR
 (column_name IN ('step_up_session','step_up_binding') AND udt_name='jsonb' AND is_nullable='YES') OR
 (column_name IN ('step_up_session_id','step_up_cookie_digest') AND udt_name='text' AND is_nullable='YES') OR
 (column_name='step_up_verified_at' AND udt_name='timestamptz' AND is_nullable='YES')))`,
		strings.TrimSpace(sessionStepUpConstraint)).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
