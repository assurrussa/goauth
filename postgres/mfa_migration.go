package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
)

const (
	localMFASchemaVersion = 9
	localMFAMigration     = "migrations/00008_local_mfa.sql"
)

func applyLocalMFAMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifySessionOIDCSchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(localMFAMigration)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_migration_history(version,checksum) VALUES($1,$2)`,
		localMFASchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES($1)`, localMFASchemaVersion)
	return err
}

func verifyLocalMFASchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(localMFAMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := q.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version=$1`,
		localMFASchemaVersion).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	err = q.QueryRowContext(ctx, `SELECT
 to_regclass('public.auth_mfa_factors') IS NOT NULL AND
 to_regclass('public.auth_mfa_recovery') IS NOT NULL AND
 to_regclass('public.auth_mfa_budget') IS NOT NULL AND
 to_regclass('public.auth_mfa_pending') IS NOT NULL AND
 to_regclass('public.auth_mfa_enrollments') IS NOT NULL AND
 to_regclass('public.auth_mfa_pending_expiry_idx') IS NOT NULL AND
 to_regclass('public.auth_mfa_enrollments_expiry_idx') IS NOT NULL`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return verifyLocalMFAColumns(ctx, q)
}

func verifyLocalMFAColumns(ctx context.Context, q queryRower) error {
	var valid bool
	err := q.QueryRowContext(ctx, `WITH expected(table_name,column_name,udt_name) AS (VALUES
 ('auth_mfa_factors','subject_id','uuid'),('auth_mfa_factors','factor_id','text'),
 ('auth_mfa_factors','revision','int8'),('auth_mfa_factors','enabled','bool'),
 ('auth_mfa_factors','key_id','text'),('auth_mfa_factors','secret','bytea'),('auth_mfa_factors','last_step','int8'),
 ('auth_mfa_recovery','subject_id','uuid'),('auth_mfa_recovery','digest','bytea'),
 ('auth_mfa_budget','subject_id','uuid'),('auth_mfa_budget','window_at','timestamptz'),('auth_mfa_budget','attempts','int4'),
 ('auth_mfa_pending','id','text'),('auth_mfa_pending','subject_id','uuid'),('auth_mfa_pending','realm','text'),
 ('auth_mfa_pending','security_version','int8'),('auth_mfa_pending','factor_id','text'),
 ('auth_mfa_pending','factor_revision','int8'),('auth_mfa_pending','binding','bytea'),
 ('auth_mfa_pending','authenticated_at','timestamptz'),('auth_mfa_pending','expires_at','timestamptz'),
 ('auth_mfa_enrollments','subject_id','uuid'),('auth_mfa_enrollments','id','text'),
 ('auth_mfa_enrollments','revision','int8'),('auth_mfa_enrollments','security_version','int8'),
 ('auth_mfa_enrollments','session_id','uuid'),('auth_mfa_enrollments','binding','bytea'),
 ('auth_mfa_enrollments','key_id','text'),('auth_mfa_enrollments','secret','bytea'),
 ('auth_mfa_enrollments','created_at','timestamptz'),('auth_mfa_enrollments','expires_at','timestamptz'))
 SELECT bool_and(c.column_name IS NOT NULL AND c.udt_name=e.udt_name AND c.is_nullable='NO')
 FROM expected e LEFT JOIN information_schema.columns c
 ON c.table_schema='public' AND c.table_name=e.table_name AND c.column_name=e.column_name`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
