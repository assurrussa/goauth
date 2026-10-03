package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
)

const subjectRetirementSchemaVersion = 6

func applySubjectRetirementMigration(ctx context.Context, tx *sql.Tx) error {
	data, err := migrationFiles.ReadFile("migrations/00005_subject_retirement.sql")
	if err != nil {
		return fmt.Errorf("read subject retirement migration: %w", err)
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return fmt.Errorf("apply subject retirement migration: %w", err)
	}
	checksum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_migration_history (version, checksum) VALUES ($1, $2)`,
		subjectRetirementSchemaVersion, hex.EncodeToString(checksum[:])); err != nil {
		return fmt.Errorf("record subject retirement migration checksum: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO goauth_schema_version (version) VALUES ($1)`,
		subjectRetirementSchemaVersion); err != nil {
		return fmt.Errorf("record subject retirement schema version: %w", err)
	}
	return nil
}

func verifySubjectRetirementSchema(ctx context.Context, db queryRower) error {
	data, err := migrationFiles.ReadFile("migrations/00005_subject_retirement.sql")
	if err != nil {
		return err
	}
	checksum := sha256.Sum256(data)
	var recorded string
	if err := db.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version = $1`,
		subjectRetirementSchemaVersion).Scan(&recorded); err != nil {
		return fmt.Errorf("read subject retirement migration history: %w", err)
	}
	if recorded != hex.EncodeToString(checksum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var columns int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_catalog.pg_attribute a
WHERE attrelid = 'public.auth_subjects'::regclass AND NOT attisdropped
  AND ((attname = 'retired_at' AND atttypid = 'pg_catalog.timestamptz'::regtype AND NOT attnotnull)
    OR (attname = 'status' AND atttypid = 'pg_catalog.text'::regtype AND attnotnull
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint n
        WHERE n.conrelid = a.attrelid AND n.contype = 'n' AND a.attnum = ANY(n.conkey)
          AND (NOT n.convalidated OR (pg_catalog.to_jsonb(n)->>'conenforced')::boolean = false)
      )))`).Scan(&columns); err != nil {
		return fmt.Errorf("inspect subject retirement columns: %w", err)
	}
	if columns != 2 {
		return ErrSchemaNeedsMigration
	}

	// A matching name alone is insufficient: a replacement CHECK (true), a
	// weakened condition or NOT VALID constraint must fail startup. Compare the
	// parsed expression's canonical, non-pretty PostgreSQL rendering rather than
	// the migration SQL's whitespace. Equivalent rewritten expressions are not
	// accepted: this verifies the supported migration, not arbitrary custom DDL.
	// Requiring validated NOT NULL status also prevents SQL's three-valued CHECK
	// semantics from admitting a retired NULL status. Older catalogs store only
	// attnotnull; PostgreSQL 18 also has potentially unvalidated NOT NULL rows.
	// conenforced was introduced in PostgreSQL 18; older versions enforce all
	// CHECK constraints. Reading via to_jsonb keeps this query compatible with
	// their catalogs while rejecting an explicitly non-enforced constraint.
	var fenced bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_constraint c
  WHERE c.conrelid = 'public.auth_subjects'::regclass
    AND c.conname = 'auth_subjects_retirement_status_check'
    AND c.contype = 'c' AND c.convalidated AND NOT c.connoinherit
    AND (pg_catalog.to_jsonb(c)->>'conenforced')::boolean IS DISTINCT FROM false
    AND pg_catalog.pg_get_expr(c.conbin, c.conrelid, false)
      = '((retired_at IS NULL) OR (status = ''disabled''::text))'
)`).Scan(&fenced); err != nil {
		return fmt.Errorf("inspect subject retirement fence: %w", err)
	}
	if !fenced {
		return ErrSchemaNeedsMigration
	}
	return nil
}
