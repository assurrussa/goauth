package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

const (
	notificationLifecycleSchemaVersion = 12
	notificationLifecycleMigration     = "migrations/00011_notification_lifecycle.sql"
)

const notificationLifecycleStateConstraint = "CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, " +
	"'blocked'::text, 'delivered'::text, 'exhausted'::text, 'expired'::text, 'cancelled'::text])))"

const notificationReceiptRetentionExpression = "GREATEST(COALESCE(delivered_at, valid_until), valid_until)"

const notificationReceiptRetentionPredicate = "((state = ANY (ARRAY['delivered'::text, 'exhausted'::text, " +
	"'expired'::text, 'cancelled'::text])) AND (ciphertext IS NULL) AND (octet_length(nonce) = 0) " +
	"AND (octet_length(additional_data) = 0) AND (lease_token IS NULL) AND (leased_until IS NULL))"

func applyNotificationLifecycleMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifyScopedEmailChangeSchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(notificationLifecycleMigration)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply notification lifecycle migration: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO goauth_migration_history(version, checksum) VALUES($1, $2)`,
		notificationLifecycleSchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES($1)`,
		notificationLifecycleSchemaVersion)
	return err
}

func verifyNotificationLifecycleSchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(notificationLifecycleMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := q.QueryRowContext(ctx,
		`SELECT checksum FROM goauth_migration_history WHERE version=$1`,
		notificationLifecycleSchemaVersion).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	if err := q.QueryRowContext(ctx, `
SELECT EXISTS (
 SELECT 1 FROM pg_constraint
 WHERE conrelid='public.auth_notification_deliveries'::regclass
  AND conname='auth_notification_deliveries_state_check' AND contype='c'
  AND convalidated AND pg_get_constraintdef(oid)=$1
) AND EXISTS (
 SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
 WHERE i.indrelid='public.auth_notification_deliveries'::regclass
  AND i.indexrelid=to_regclass('public.auth_notification_deliveries_receipt_cleanup_idx')
  AND a.amname='btree' AND i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
  AND i.indnatts=2 AND i.indnkeyatts=2 AND i.indexprs IS NOT NULL
  AND i.indoption[0]=0 AND i.indoption[1]=0
  AND pg_get_indexdef(i.indexrelid,1,true)=$2 AND pg_get_indexdef(i.indexrelid,2,true)='id'
  AND pg_get_expr(i.indpred,i.indrelid)=$3
)`, notificationLifecycleStateConstraint,
		notificationReceiptRetentionExpression, notificationReceiptRetentionPredicate).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
