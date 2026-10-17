package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

const (
	assistedRecoverySchemaVersion = 14
	assistedRecoveryMigration     = "migrations/00013_assisted_recovery.sql"
)

func applyAssistedRecoveryMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifyNotificationSenderDiagnosticsSchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(assistedRecoveryMigration)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply assisted recovery migration: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO goauth_migration_history(version,checksum) VALUES($1,$2)`,
		assistedRecoverySchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES($1)`, assistedRecoverySchemaVersion)
	return err
}

func verifyAssistedRecoverySchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(assistedRecoveryMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := q.QueryRowContext(ctx,
		`SELECT checksum FROM goauth_migration_history WHERE version=$1`,
		assistedRecoverySchemaVersion).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var columns int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public'
 AND table_name='auth_assisted_recovery' AND column_name IN
 ('selector','subject_id','actor_id','key_id','secret_digest','security_version','old_email','new_email',
 'created_at','expires_at','scope','target_version','owner_cli')`).Scan(&columns); err != nil {
		return err
	}
	if columns != 13 {
		return ErrSchemaNeedsMigration
	}
	return nil
}
