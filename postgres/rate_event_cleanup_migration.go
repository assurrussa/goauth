package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

const rateEventCleanupSchemaVersion = 7

func applyRateEventCleanupMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifySubjectRetirementSchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile("migrations/00006_rate_event_cleanup.sql")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply rate event retention index: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_migration_history (version, checksum) VALUES ($1, $2)`,
		rateEventCleanupSchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return fmt.Errorf("record rate event cleanup migration checksum: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_schema_version (version) VALUES ($1)`,
		rateEventCleanupSchemaVersion); err != nil {
		return fmt.Errorf("record rate event cleanup schema version: %w", err)
	}
	return nil
}

func verifyRateEventCleanupSchema(ctx context.Context, db queryRower) error {
	data, err := migrationFiles.ReadFile("migrations/00006_rate_event_cleanup.sql")
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := db.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version = $1`,
		rateEventCleanupSchemaVersion).Scan(&recorded); err != nil {
		return fmt.Errorf("read rate event cleanup migration history: %w", err)
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
 WHERE i.indrelid='public.auth_rate_limit_events'::regclass
 AND c.relname='auth_rate_limit_events_retention_idx' AND a.amname='btree'
 AND i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
 AND i.indnatts=2 AND i.indnkeyatts=2 AND i.indpred IS NULL AND i.indexprs IS NULL
 AND i.indoption[0]=0 AND i.indoption[1]=0
 AND pg_get_indexdef(i.indexrelid,1,true)='occurred_at'
 AND pg_get_indexdef(i.indexrelid,2,true)='id'
)`).Scan(&valid); err != nil {
		return fmt.Errorf("inspect rate event retention index: %w", err)
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
