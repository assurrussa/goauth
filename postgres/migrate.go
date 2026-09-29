package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
)

const schemaVersion = 3

// ResetConfirmation is intentionally a distinct type so destructive schema
// resets cannot receive an arbitrary runtime string by accident.
type ResetConfirmation string

// ConfirmResetAuthState must be passed explicitly to Down. Keeping the value
// typed prevents ordinary runtime strings from crossing the destructive API.
const ConfirmResetAuthState ResetConfirmation = "RESET GOAUTH AUTH STATE"

var (
	ErrLegacySchemaRequiresReset = errors.New("goauth v0.1 schema requires an explicit dev/test reset")
	ErrResetConfirmationRequired = errors.New("explicit goauth reset confirmation is required")
	ErrFutureSchema              = errors.New("goauth database schema is newer than this library")
	ErrSchemaNeedsMigration      = errors.New("goauth database schema requires migration")
	ErrSchemaChecksumMismatch    = errors.New("goauth migration checksum mismatch")
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("PostgreSQL database is required")
	}
	// READ COMMITTED gives the schema inspection a new snapshot after a
	// concurrent migrator commits and releases the advisory lock.
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin goauth migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	const lockID int64 = 6686167654426882759
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return fmt.Errorf("lock goauth migrations: %w", err)
	}

	state, err := detectSchema(ctx, tx)
	if err != nil {
		return err
	}
	switch state {
	case schemaStateV3:
		// No schema change is needed, but still finish the transaction to release
		// the lock before reporting a successful verification.
	case schemaStateFuture:
		return ErrFutureSchema
	case schemaStateLegacy:
		return ErrLegacySchemaRequiresReset
	case schemaStateEmpty:
		if err := applyBaseline(ctx, tx); err != nil {
			return err
		}
		fallthrough
	case schemaStateV2:
		if err := applyNotificationMigration(ctx, tx); err != nil {
			return err
		}
	default:
		return errors.New("unknown goauth schema state")
	}
	if err := verifySchema(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit goauth migration: %w", err)
	}
	return nil
}

func applyBaseline(ctx context.Context, tx *sql.Tx) error {
	sqlBytes, err := migrationFiles.ReadFile("migrations/00001_v0_2_baseline.sql")
	if err != nil {
		return fmt.Errorf("read embedded goauth v0.2 migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("apply goauth v0.2 baseline: %w", err)
	}
	return nil
}

func applyNotificationMigration(ctx context.Context, tx *sql.Tx) error {
	sqlBytes, err := migrationFiles.ReadFile("migrations/00002_notifications.sql")
	if err != nil {
		return fmt.Errorf("read embedded notification migration: %w", err)
	}
	checksum := sha256.Sum256(sqlBytes)
	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("apply notification migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_migration_history (version, checksum) VALUES ($1, $2)`,
		schemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return fmt.Errorf("record notification migration checksum: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_schema_version (version) VALUES ($1)`, schemaVersion); err != nil {
		return fmt.Errorf("record notification schema version: %w", err)
	}
	return nil
}

// VerifySchema checks the schema version, notification migration checksum,
// required tables, and notification queue column names without changing the
// database. It does not compare every type, index, foreign key, or constraint.
// Callers with AutoMigrate disabled get this check at Runtime construction.
func VerifySchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("PostgreSQL database is required")
	}
	return verifySchema(ctx, db)
}

func verifySchema(ctx context.Context, db queryRower) error {
	state, err := detectSchema(ctx, db)
	if err != nil {
		return err
	}
	if state == schemaStateFuture {
		return ErrFutureSchema
	}
	if state != schemaStateV3 {
		return ErrSchemaNeedsMigration
	}
	var historyTable, queueTable sql.NullString
	if err := db.QueryRowContext(ctx, `
SELECT to_regclass('public.goauth_migration_history')::text,
       to_regclass('public.auth_notification_deliveries')::text`).Scan(&historyTable, &queueTable); err != nil {
		return fmt.Errorf("inspect goauth migration tables: %w", err)
	}
	if !historyTable.Valid || !queueTable.Valid {
		return ErrSchemaNeedsMigration
	}
	sqlBytes, err := migrationFiles.ReadFile("migrations/00002_notifications.sql")
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(sqlBytes)
	var recorded string
	if err := db.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version = $1`,
		schemaVersion).Scan(&recorded); err != nil {
		return fmt.Errorf("read goauth migration history: %w", err)
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var requiredColumns int
	if err := db.QueryRowContext(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'auth_notification_deliveries'
  AND column_name IN (
    'id', 'subject_id', 'event_type', 'reference_id', 'valid_until',
    'key_id', 'nonce', 'ciphertext', 'additional_data', 'created_at',
    'delete_after', 'state', 'attempts', 'next_attempt_at', 'lease_token',
    'leased_until', 'delivered_at', 'last_failure'
  )`).Scan(&requiredColumns); err != nil {
		return fmt.Errorf("inspect notification columns: %w", err)
	}
	if requiredColumns != 18 {
		return ErrSchemaNeedsMigration
	}
	return nil
}

// Down removes canonical auth state, including managed notifications, and requires an exact
// confirmation value. It is intended for isolated development and test
// databases; Migrate never calls it implicitly.
func Down(ctx context.Context, db *sql.DB, confirmation ResetConfirmation) error {
	if confirmation != ConfirmResetAuthState {
		return ErrResetConfirmationRequired
	}
	if db == nil {
		return errors.New("PostgreSQL database is required")
	}

	const statement = `
DROP TABLE IF EXISTS auth_security_audit_events;
DROP TABLE IF EXISTS auth_notification_deliveries;
DROP TABLE IF EXISTS goauth_migration_history;
DROP TABLE IF EXISTS auth_rate_limit_events;
DROP TABLE IF EXISTS auth_subject_roles;
DROP TABLE IF EXISTS auth_role_permissions;
DROP TABLE IF EXISTS auth_roles;
DROP TABLE IF EXISTS auth_permissions;
DROP TABLE IF EXISTS auth_identity_links;
DROP TABLE IF EXISTS auth_email_change_records;
DROP TABLE IF EXISTS auth_email_challenges;
DROP TABLE IF EXISTS auth_password_reset_records;
DROP TABLE IF EXISTS auth_oidc_refresh_tokens;
DROP TABLE IF EXISTS auth_oidc_refresh_families;
DROP TABLE IF EXISTS auth_refresh_tokens;
DROP TABLE IF EXISTS auth_refresh_families;
DROP TABLE IF EXISTS auth_sessions;

-- v0.1-only tables are intentionally removable only through this confirmed
-- development/test reset path. Published v0.1 migrations remain immutable.
DROP TABLE IF EXISTS auth_confirmation_codes;
DROP TABLE IF EXISTS auth_confirmations;
DROP TABLE IF EXISTS auth_email_change_requests;
DROP TABLE IF EXISTS auth_external_identities;
DROP TABLE IF EXISTS auth_password_reset_tokens;
DROP TABLE IF EXISTS auth_sso_identity_links;

DROP TABLE IF EXISTS auth_local_credentials;
DROP TABLE IF EXISTS auth_basic_profiles;
DROP TABLE IF EXISTS auth_identifiers;
DROP TABLE IF EXISTS auth_subjects;
DROP TABLE IF EXISTS goauth_schema_version;
DROP TABLE IF EXISTS goauth_goose_db_version;`

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin goauth schema reset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("reset goauth auth schema: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit goauth schema reset: %w", err)
	}

	return nil
}

type schemaState uint8

const (
	schemaStateEmpty schemaState = iota
	schemaStateLegacy
	schemaStateV2
	schemaStateV3
	schemaStateFuture
)

func detectSchema(ctx context.Context, db queryRower) (schemaState, error) {
	var subjectsTable sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.auth_subjects')::text`).Scan(&subjectsTable); err != nil {
		return schemaStateEmpty, fmt.Errorf("detect auth_subjects table: %w", err)
	}
	if !subjectsTable.Valid || subjectsTable.String == "" {
		return schemaStateEmpty, nil
	}

	var versionTable sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.goauth_schema_version')::text`).Scan(&versionTable); err != nil {
		return schemaStateEmpty, fmt.Errorf("detect goauth schema version table: %w", err)
	}
	if !versionTable.Valid || versionTable.String == "" {
		return schemaStateLegacy, nil
	}

	var version int
	if err := db.QueryRowContext(ctx, `SELECT max(version) FROM goauth_schema_version`).Scan(&version); err != nil {
		return schemaStateEmpty, fmt.Errorf("read goauth schema version: %w", err)
	}
	if version > schemaVersion {
		return schemaStateFuture, nil
	}
	if version != 2 && version != schemaVersion {
		return schemaStateLegacy, nil
	}

	var requiredColumns int
	if err := db.QueryRowContext(ctx, `
SELECT count(*)
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'auth_subjects'
  AND column_name IN ('status', 'security_version')`).Scan(&requiredColumns); err != nil {
		return schemaStateEmpty, fmt.Errorf("inspect auth_subjects columns: %w", err)
	}
	if requiredColumns != 2 {
		return schemaStateLegacy, nil
	}

	if version == schemaVersion {
		return schemaStateV3, nil
	}
	return schemaStateV2, nil
}
