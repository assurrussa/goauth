package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

const (
	notificationGatewayMigration         = "migrations/00014_notification_gateway.sql"
	notificationGatewayReceiptConstraint = "CHECK ((((gateway_receipt_id IS NULL) AND (gateway_accepted_at IS NULL) AND (state <> " +
		"'gateway_accepted'::text)) OR ((gateway_receipt_id IS NOT NULL) AND " +
		"((gateway_receipt_id)::text ~ '^[A-Za-z0-9_.:-]{1,128}$'::text) AND (gateway_accepted_at " +
		"IS NOT NULL) AND (ciphertext IS NULL) AND (octet_length(nonce) = 0) AND " +
		"(octet_length(additional_data) = 0) AND (state = ANY (ARRAY['gateway_accepted'::text, " +
		"'leased'::text, 'delivered'::text, 'exhausted'::text, 'expired'::text])))))"
)

const (
	notificationGatewayProtocolConstraint = "CHECK (((transport_protocol)::text ~ '^[A-Za-z0-9_-]{0,64}$'::text))"
	notificationGatewayStateConstraint    = "CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, 'blocked'::text, " +
		"'delivered'::text, 'exhausted'::text, 'expired'::text, 'cancelled'::text, " +
		"'gateway_accepted'::text])))"
)

func applyNotificationGatewayMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifyAssistedRecoverySchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(notificationGatewayMigration)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply notification gateway migration: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO goauth_migration_history(version,checksum) VALUES(15,$1)`,
		hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES(15)`)
	return err
}

func verifyNotificationGatewaySchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(notificationGatewayMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err = q.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version=15`).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	if err = q.QueryRowContext(ctx, `SELECT
 EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='auth_notification_deliveries'
 AND column_name='transport_protocol' AND udt_name='varchar' AND character_maximum_length=64 AND is_nullable='NO'
 AND column_default=$5 AND domain_name IS NULL AND collation_name IS NULL AND is_generated='NEVER' AND is_identity='NO')
 AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='auth_notification_deliveries'
 AND column_name='gateway_receipt_id' AND udt_name='varchar' AND character_maximum_length=128 AND is_nullable='YES'
 AND column_default IS NULL)
 AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='auth_notification_deliveries'
 AND column_name='gateway_accepted_at' AND udt_name='timestamptz' AND is_nullable='YES' AND column_default IS NULL)
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.auth_notification_deliveries'::regclass
 AND conname='auth_notification_deliveries_state_check' AND contype='c' AND convalidated AND pg_get_constraintdef(oid)=$1)
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.auth_notification_deliveries'::regclass
 AND conname='auth_notification_gateway_receipt_check' AND contype='c' AND convalidated
 AND NOT connoinherit AND pg_get_constraintdef(oid)=$2)
 AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='public.auth_notification_deliveries'::regclass
 AND conname='auth_notification_transport_protocol_check' AND contype='c' AND convalidated
 AND NOT connoinherit AND pg_get_constraintdef(oid)=$3)
 AND EXISTS(SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('public.auth_notification_gateway_ready_idx')
 AND indrelid='public.auth_notification_deliveries'::regclass AND indisvalid AND indisready AND indislive
 AND NOT indisunique AND indnatts=2 AND indnkeyatts=2 AND indexprs IS NULL
 AND indoption[0]=0 AND indoption[1]=0
 AND pg_get_indexdef(indexrelid,1,true)='next_attempt_at' AND pg_get_indexdef(indexrelid,2,true)='created_at'
 AND pg_get_expr(indpred,indrelid)= $4)`, notificationGatewayStateConstraint, notificationGatewayReceiptConstraint,
		notificationGatewayProtocolConstraint,
		notificationGatewayReadyPredicate, "''::character varying").Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}

const notificationGatewayReadyPredicate = "((gateway_receipt_id IS NOT NULL) AND " +
	"(state = ANY (ARRAY['gateway_accepted'::text, 'leased'::text])))"
