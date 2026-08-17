package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
)

const schemaVersion = 2

// ResetConfirmation is intentionally a distinct type so destructive schema
// resets cannot receive an arbitrary runtime string by accident.
type ResetConfirmation string

// ConfirmResetAuthState must be passed explicitly to Down. Keeping the value
// typed prevents ordinary runtime strings from crossing the destructive API.
const ConfirmResetAuthState ResetConfirmation = "RESET GOAUTH AUTH STATE"

var (
	ErrLegacySchemaRequiresReset = errors.New("goauth v0.1 schema requires an explicit dev/test reset")
	ErrResetConfirmationRequired = errors.New("explicit goauth reset confirmation is required")
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("PostgreSQL database is required")
	}

	state, err := detectSchema(ctx, db)
	if err != nil {
		return err
	}
	switch state {
	case schemaStateV2:
		return nil
	case schemaStateLegacy:
		return ErrLegacySchemaRequiresReset
	case schemaStateEmpty:
	default:
		return errors.New("unknown goauth schema state")
	}

	sqlBytes, err := migrationFiles.ReadFile("migrations/00001_v0_2_baseline.sql")
	if err != nil {
		return fmt.Errorf("read embedded goauth v0.2 migration: %w", err)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin goauth v0.2 migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("apply goauth v0.2 baseline: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit goauth v0.2 baseline: %w", err)
	}

	return nil
}

// Down removes canonical v0.1 or v0.2 auth state and requires an exact
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
DROP TABLE IF EXISTS role_hierarchy;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;

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
)

func detectSchema(ctx context.Context, db *sql.DB) (schemaState, error) {
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
	if version != schemaVersion {
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

	return schemaStateV2, nil
}
