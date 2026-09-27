//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
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
	identifierID := goauth.NewSubjectID()
	sessionID := goauth.NewSubjectID()
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `
INSERT INTO auth_subjects (id, status, security_version, created_at, updated_at)
VALUES ($1, 'active', 1, $2, $2)`, subjectID, now)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `
INSERT INTO auth_identifiers (id, subject_id, scheme, display_value, normalized_value,
    is_primary, created_at, updated_at)
VALUES ($1, $2, 'email', 'upgrade@example.test', 'upgrade@example.test', true, $3, $3)`,
		identifierID, subjectID, now)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `
INSERT INTO auth_local_credentials (subject_id, password_phc, created_at, updated_at)
VALUES ($1, '$argon2id$upgrade-fixture', $2, $2)`, subjectID, now)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `
INSERT INTO auth_sessions (id, subject_id, realm, scope, security_version, created_at, expires_at)
VALUES ($1, $2, 'user', 'authenticated', 1, $3, $4)`, sessionID, subjectID, now, now.Add(time.Hour))
	require.NoError(t, err)
	var roleID int64
	require.NoError(t, db.QueryRowContext(ctx, `
INSERT INTO auth_roles (public_id, slug, name)
VALUES ($1, 'upgrade-role', 'Upgrade Role') RETURNING id`, goauth.NewSubjectID()).Scan(&roleID))
	_, err = db.ExecContext(ctx, `INSERT INTO auth_subject_roles (subject_id, role_id) VALUES ($1, $2)`, subjectID, roleID)
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
	for _, query := range []string{
		`SELECT count(*) FROM auth_identifiers WHERE subject_id = $1 AND normalized_value = 'upgrade@example.test'`,
		`SELECT count(*) FROM auth_local_credentials WHERE subject_id = $1 AND password_phc = '$argon2id$upgrade-fixture'`,
		`SELECT count(*) FROM auth_sessions WHERE subject_id = $1 AND realm = 'user'`,
		`SELECT count(*) FROM auth_subject_roles WHERE subject_id = $1`,
	} {
		var preserved int
		require.NoError(t, db.QueryRowContext(ctx, query, subjectID).Scan(&preserved))
		require.Equal(t, 1, preserved, "v0.2 row must survive notification migration: %s", query)
	}

	var originalChecksum string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT checksum FROM goauth_migration_history WHERE version = 3`).Scan(&originalChecksum))
	t.Cleanup(func() {
		_, cleanupErr := db.ExecContext(context.Background(), `DELETE FROM goauth_schema_version WHERE version = 4`)
		require.NoError(t, cleanupErr)
		_, cleanupErr = db.ExecContext(context.Background(),
			`UPDATE goauth_migration_history SET checksum = $1 WHERE version = 3`, originalChecksum)
		require.NoError(t, cleanupErr)
	})
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

func TestMigrationFailureRollsBackAndCanRetry(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	ctx := context.Background()

	// This table collides with the second migration. The baseline, version
	// rows, and the advisory lock must all be rolled back together.
	_, err := db.ExecContext(ctx, `CREATE TABLE auth_notification_deliveries (id bigint)`)
	require.NoError(t, err)
	require.Error(t, postgres.Migrate(ctx, db))
	var subjects sql.NullString
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regclass('public.auth_subjects')::text`).Scan(&subjects))
	require.False(t, subjects.Valid, "failed migration must leave no partial baseline")
	_, err = db.ExecContext(ctx, `DROP TABLE auth_notification_deliveries`)
	require.NoError(t, err)
	retryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	require.NoError(t, postgres.Migrate(retryCtx, db))
	require.NoError(t, postgres.VerifySchema(ctx, db))
}

func TestMigrationCancellationWhileWaitingForLock(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	ctx := context.Background()
	const lockID int64 = 6686167654426882759
	holder, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback() }()
	_, err = holder.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID)
	require.NoError(t, err)

	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = postgres.Migrate(waitCtx, db)
	require.Error(t, err)
	require.ErrorIs(t, waitCtx.Err(), context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second)

	require.NoError(t, holder.Commit())
	retryCtx, retryCancel := context.WithTimeout(ctx, 10*time.Second)
	defer retryCancel()
	require.NoError(t, postgres.Migrate(retryCtx, db), "canceled waiter must not retain a lock")
	require.NoError(t, postgres.VerifySchema(ctx, db))
}
