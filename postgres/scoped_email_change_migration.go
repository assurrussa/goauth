package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
)

const (
	scopedEmailChangeSchemaVersion = 11
	scopedEmailChangeMigration     = "migrations/00010_scoped_email_change.sql"
)

const scopedEmailSnapshotConstraint = "CHECK ((((scope = ''::text) AND (expected_security_version IS NULL) AND " +
	"(target_version IS NULL) AND (old_normalized_value IS NULL)) OR " +
	"((scope ~ '^[a-z0-9_.-]{1,64}$'::text) AND (expected_security_version IS NOT NULL) AND " +
	"(expected_security_version > 0) AND (target_version IS NOT NULL) AND (target_version > 0) AND " +
	"(old_normalized_value IS NOT NULL))))"

const scopedEmailPendingIndex = "CREATE INDEX auth_email_change_scope_pending_idx ON public.auth_email_change_records " +
	"USING btree (subject_id, scope, created_at DESC, id DESC) WHERE (consumed_at IS NULL)"

func applyScopedEmailChangeMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifyRequiredMFASchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(scopedEmailChangeMigration)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO goauth_migration_history(version, checksum) VALUES($1, $2)`,
		scopedEmailChangeSchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES($1)`, scopedEmailChangeSchemaVersion)
	return err
}

func verifyScopedEmailChangeSchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(scopedEmailChangeMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := q.QueryRowContext(ctx,
		`SELECT checksum FROM goauth_migration_history WHERE version = $1`,
		scopedEmailChangeSchemaVersion).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	err = q.QueryRowContext(ctx, `
WITH expected(column_name, udt_name, nullable) AS (VALUES
 ('scope', 'text', 'NO'), ('expected_security_version', 'int8', 'YES'),
 ('target_version', 'int8', 'YES'), ('old_normalized_value', 'text', 'YES'))
SELECT bool_and(c.column_name IS NOT NULL AND c.udt_name = e.udt_name AND c.is_nullable = e.nullable
 AND c.domain_name IS NULL AND c.collation_name IS NULL AND c.is_generated = 'NEVER'
 AND c.is_identity = 'NO' AND c.udt_schema = 'pg_catalog'
 AND COALESCE(c.column_default, '') = CASE WHEN e.column_name = 'scope' THEN $3 ELSE '' END)
 AND EXISTS (
  SELECT 1 FROM pg_constraint WHERE conrelid = 'auth_email_change_records'::regclass
  AND conname = 'auth_email_change_scope_snapshot' AND contype = 'c' AND convalidated
  AND pg_get_constraintdef(oid) = $1
 )
 AND EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('public.auth_email_change_scope_pending_idx')
  AND indisvalid AND indisready AND pg_get_indexdef(indexrelid) = $2)
FROM expected e LEFT JOIN information_schema.columns c
 ON c.table_schema = 'public' AND c.table_name = 'auth_email_change_records' AND c.column_name = e.column_name
`, scopedEmailSnapshotConstraint, scopedEmailPendingIndex, "''::text").Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
