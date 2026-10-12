package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const requiredMFAMigration = "migrations/00009_required_mfa.sql"

//go:embed mfa_required_schema.json
var requiredMFASchemaJSON []byte

type mfaSchemaExpectation struct {
	Table      string `json:"table"`
	Name       string `json:"name,omitempty"`
	Definition string `json:"definition,omitempty"`
	Column     string `json:"column,omitempty"`
	Default    string `json:"default,omitempty"`
}

func applyRequiredMFAMigration(ctx context.Context, tx *sql.Tx) error {
	if err := verifyLocalMFASchema(ctx, tx); err != nil {
		return err
	}
	data, err := migrationFiles.ReadFile(requiredMFAMigration)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, string(data)); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO goauth_migration_history(version,checksum) VALUES(10,$1)`, hex.EncodeToString(sum[:]),
	); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO goauth_schema_version(version) VALUES(10)`)
	return err
}

func verifyRequiredMFASchema(ctx context.Context, q queryRower) error {
	data, err := migrationFiles.ReadFile(requiredMFAMigration)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	var recorded string
	if err := q.QueryRowContext(ctx, `SELECT checksum FROM goauth_migration_history WHERE version=10`).Scan(&recorded); err != nil {
		return err
	}
	if recorded != hex.EncodeToString(sum[:]) {
		return ErrSchemaChecksumMismatch
	}
	var valid bool
	err = q.QueryRowContext(ctx, `WITH expected(table_name,column_name,udt_name) AS (VALUES
 ('auth_sessions','mfa_admission','text'),('auth_mfa_pending','kind','text'),
 ('auth_mfa_pending','setup_id','text'),('auth_mfa_pending','setup_key_id','text'),
 ('auth_mfa_pending','setup_secret','bytea'),('auth_mfa_pending','setup_recovery','bytea'))
 SELECT bool_and(c.column_name IS NOT NULL AND c.udt_name=e.udt_name AND c.is_nullable='NO')
 FROM expected e LEFT JOIN information_schema.columns c
 ON c.table_schema='public' AND c.table_name=e.table_name AND c.column_name=e.column_name`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return verifyMFASecurityDefinitions(ctx, q)
}

// Validate the live schema, not merely its recorded migration checksum.
// Exact server-normalized definitions also reject same-named weakened CHECKs.
func verifyMFASecurityDefinitions(ctx context.Context, q queryRower) error {
	var spec struct {
		Constraints []mfaSchemaExpectation `json:"constraints"`
		Defaults    []mfaSchemaExpectation `json:"defaults"`
		Indexes     []mfaSchemaExpectation `json:"indexes"`
	}
	if err := json.Unmarshal(requiredMFASchemaJSON, &spec); err != nil {
		return err
	}
	for _, item := range spec.Constraints {
		var valid bool
		err := q.QueryRowContext(ctx, `SELECT convalidated AND pg_get_constraintdef(oid)=$3
 FROM pg_constraint WHERE conrelid=to_regclass('public.' || $1) AND conname=$2`,
			item.Table, item.Name, item.Definition).Scan(&valid)
		if err := mfaSchemaDefinitionResult(valid, err); err != nil {
			return err
		}
	}
	for _, item := range spec.Defaults {
		var valid bool
		err := q.QueryRowContext(ctx, `SELECT COALESCE(column_default=$3,false) FROM information_schema.columns
 WHERE table_schema='public' AND table_name=$1 AND column_name=$2`,
			item.Table, item.Column, item.Default).Scan(&valid)
		if err := mfaSchemaDefinitionResult(valid, err); err != nil {
			return err
		}
	}
	for _, item := range spec.Indexes {
		var valid bool
		err := q.QueryRowContext(ctx, `SELECT i.indisvalid AND i.indisready AND pg_get_indexdef(i.indexrelid)=$3
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
 WHERE i.indrelid=to_regclass('public.' || $1) AND c.relname=$2`,
			item.Table, item.Name, item.Definition).Scan(&valid)
		if err := mfaSchemaDefinitionResult(valid, err); err != nil {
			return err
		}
	}
	return nil
}

func mfaSchemaDefinitionResult(valid bool, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSchemaNeedsMigration
	}
	if err != nil {
		return err
	}
	if !valid {
		return ErrSchemaNeedsMigration
	}
	return nil
}
