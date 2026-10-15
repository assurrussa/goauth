package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

const (
	notificationSenderDiagnosticsSchemaVersion = 13
	notificationSenderDiagnosticsMigration     = "migrations/00012_notification_sender_diagnostics.sql"
)

func applyNotificationSenderDiagnosticsMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifyNotificationLifecycleSchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(notificationSenderDiagnosticsMigration)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply notification sender diagnostics migration: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO goauth_migration_history(version, checksum) VALUES($1, $2)`,
		notificationSenderDiagnosticsSchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES($1)`,
		notificationSenderDiagnosticsSchemaVersion)
	return err
}

func verifyNotificationSenderDiagnosticsSchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(notificationSenderDiagnosticsMigration)
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := q.QueryRowContext(ctx,
		`SELECT checksum FROM goauth_migration_history WHERE version=$1`,
		notificationSenderDiagnosticsSchemaVersion).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	if err := q.QueryRowContext(ctx, `
WITH expected(column_name,udt_name,max_length) AS (VALUES
 ('last_sender_outcome','varchar',32), ('last_sender_code','varchar',64),
 ('last_sender_http_status','int4',NULL), ('last_sender_attempt','int4',NULL),
 ('last_sender_observed_at','timestamptz',NULL))
SELECT bool_and(c.column_name IS NOT NULL AND c.udt_name=e.udt_name AND c.is_nullable='YES'
 AND c.character_maximum_length IS NOT DISTINCT FROM e.max_length
 AND c.column_default IS NULL AND c.domain_name IS NULL AND c.collation_name IS NULL
 AND c.is_generated='NEVER' AND c.is_identity='NO' AND c.udt_schema='pg_catalog'
 AND (e.udt_name<>'timestamptz' OR c.datetime_precision=6))
FROM expected e LEFT JOIN information_schema.columns c
 ON c.table_schema='public' AND c.table_name='auth_notification_deliveries' AND c.column_name=e.column_name`).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	for name, definition := range notificationSenderDiagnosticConstraints {
		if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint
WHERE conrelid='public.auth_notification_deliveries'::regclass AND conname=$1
 AND contype='c' AND convalidated AND NOT connoinherit AND pg_get_constraintdef(oid)=$2)`, name, definition).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return ErrSchemaNeedsMigration
		}
	}
	return nil
}

var notificationSenderDiagnosticConstraints = map[string]string{
	"auth_notification_sender_outcome_check":  "CHECK (((last_sender_outcome)::text = ANY (ARRAY['not_sent'::text, 'retryable'::text, 'rejected'::text, 'unknown'::text, 'simulated'::text])))",
	"auth_notification_sender_code_check":     "CHECK (((last_sender_code)::text = ANY (ARRAY['invalid_request'::text, 'context_done'::text, 'expired'::text, 'request_failed'::text, 'invalid_response'::text, 'idempotency_conflict'::text, 'unauthorized'::text, 'endpoint_unavailable'::text, 'request_too_large'::text, 'quota_exceeded'::text, 'simulated'::text, 'dispatching'::text, 'unknown'::text, 'retry'::text, 'failed'::text, 'provider_rejected_temporary'::text, 'provider_rejected'::text, 'dispatch_outcome_unknown'::text, 'dispatch_in_progress'::text, 'dry_run_no_external_delivery'::text, 'recipient_suppressed'::text, 'retry_budget_exhausted'::text])))",
	"auth_notification_sender_http_check":     "CHECK (((last_sender_http_status >= 100) AND (last_sender_http_status <= 599)))",
	"auth_notification_sender_attempt_check":  "CHECK (((last_sender_attempt > 0) AND (last_sender_attempt <= attempts)))",
	"auth_notification_sender_snapshot_check": "CHECK ((((last_sender_outcome IS NULL) AND (last_sender_code IS NULL) AND (last_sender_http_status IS NULL) AND (last_sender_attempt IS NULL) AND (last_sender_observed_at IS NULL)) OR ((last_sender_outcome IS NOT NULL) AND (last_sender_code IS NOT NULL) AND (last_sender_attempt IS NOT NULL) AND (last_sender_observed_at IS NOT NULL))))",
}
