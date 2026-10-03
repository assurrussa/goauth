package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

func applyNotificationExpiryMigration(ctx context.Context, tx *sql.Tx) error {
	data, err := migrationFiles.ReadFile("migrations/00004_notification_expiry.sql")
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply notification expiry index: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err = tx.ExecContext(ctx, `INSERT INTO goauth_migration_history(version,checksum) VALUES($1,$2)`,
		notificationExpirySchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES($1)`, notificationExpirySchemaVersion)
	return err
}

func verifyNotificationExpirySchema(ctx context.Context, db queryRower) error {
	data, err := migrationFiles.ReadFile("migrations/00004_notification_expiry.sql")
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err = db.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version=$1`,
		notificationExpirySchemaVersion).Scan(&recorded); err != nil {
		return fmt.Errorf("read notification expiry migration history: %w", err)
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	// Verify both query assumptions: the valid deadline is never after retention,
	// and the named partial B-tree really supports this predicate and key order.
	var valid bool
	err = db.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.auth_notification_deliveries'::regclass
  AND contype='c' AND convalidated AND pg_get_constraintdef(oid)='CHECK ((valid_until <= delete_after))')
 AND EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
  WHERE i.indrelid='public.auth_notification_deliveries'::regclass
  AND c.relname='auth_notification_deliveries_expiry_idx' AND a.amname='btree'
  AND i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
  AND i.indnatts=2 AND i.indnkeyatts=2
  AND pg_get_indexdef(i.indexrelid,1,true)='valid_until'
  AND pg_get_indexdef(i.indexrelid,2,true)='id'
  AND pg_get_expr(i.indpred,i.indrelid)='(ciphertext IS NOT NULL)')`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
