//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestNotificationMigrationUpgradesV2WithoutLosingSubjects(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	ctx := context.Background()
	require.NoError(t, postgres.Migrate(ctx, db))
	subjectID := goauth.NewSubjectID()
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `
INSERT INTO auth_subjects (id, status, security_version, created_at, updated_at)
VALUES ($1, 'active', 1, $2, $2)`, subjectID, now)
	require.NoError(t, err)

	// Recreate the previous published schema state without touching canonical
	// auth rows or the immutable baseline tables.
	_, err = db.ExecContext(ctx, `
DROP TABLE auth_notification_deliveries;
DROP TABLE goauth_migration_history;
DELETE FROM goauth_schema_version WHERE version = 3;`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(ctx, db), postgres.ErrSchemaNeedsMigration)
	_, err = postgres.NewRuntime(postgres.Config{DB: db, Runtime: runtimeConfig(t)})
	require.ErrorIs(t, err, postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(ctx, db))
	require.NoError(t, postgres.VerifySchema(ctx, db))
	require.NoError(t, postgres.Migrate(ctx, db), "repeat migration must be idempotent")
	var subjects int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM auth_subjects WHERE id = $1`, subjectID).Scan(&subjects))
	require.Equal(t, 1, subjects)

	_, err = db.ExecContext(ctx, `UPDATE goauth_migration_history SET checksum = 'altered' WHERE version = 3`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(ctx, db), postgres.ErrSchemaChecksumMismatch)
	require.ErrorIs(t, postgres.Migrate(ctx, db), postgres.ErrSchemaChecksumMismatch)
	_, err = db.ExecContext(ctx, `INSERT INTO goauth_schema_version (version) VALUES (4)`)
	require.NoError(t, err)
	require.True(t, errors.Is(postgres.Migrate(ctx, db), postgres.ErrFutureSchema))
}

func TestConcurrentNotificationMigrationIsSerialized(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	ctx := context.Background()
	const callers = 6
	var wait sync.WaitGroup
	errorsCh := make(chan error, callers)
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsCh <- postgres.Migrate(ctx, db)
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		require.NoError(t, err)
	}
	var history int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM goauth_migration_history WHERE version = 3`).Scan(&history))
	require.Equal(t, 1, history)
}
