package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

func applyLocalIdentityMigration(ctx context.Context, tx *sql.Tx) error {
	data, err := migrationFiles.ReadFile("migrations/00003_local_identity.sql")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply local identity migration: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_migration_history (version, checksum) VALUES ($1, $2)`,
		localIdentitySchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version (version) VALUES ($1)`, localIdentitySchemaVersion)
	return err
}

func verifyLocalIdentitySchema(ctx context.Context, db queryRower) error {
	data, err := migrationFiles.ReadFile("migrations/00003_local_identity.sql")
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := db.QueryRowContext(ctx,
		`SELECT checksum FROM goauth_migration_history WHERE version = $1`, localIdentitySchemaVersion).Scan(&recorded); err != nil {
		return fmt.Errorf("read local identity migration history: %w", err)
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var columns int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
 WHERE table_schema = 'public' AND table_name = 'auth_local_credentials'
 AND column_name = 'password_input_policy' AND is_nullable = 'NO' AND data_type = 'text'`).Scan(&columns); err != nil {
		return err
	}
	if columns != 1 {
		return ErrSchemaNeedsMigration
	}
	return nil
}
