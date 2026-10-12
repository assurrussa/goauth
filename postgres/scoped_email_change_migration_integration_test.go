//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

func removeScopedEmailSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
ALTER TABLE auth_email_change_records DROP COLUMN scope,DROP COLUMN expected_security_version,
 DROP COLUMN target_version,DROP COLUMN old_normalized_value;
DELETE FROM goauth_migration_history WHERE version=11;
DELETE FROM goauth_schema_version WHERE version=11;`)
	require.NoError(t, err)
}

func TestScopedEmailMigrationPreservesPrimaryChallengeAndChecksums(t *testing.T) {
	f := newScopedEmailFixture(t)
	require.NoError(t, f.runtime.RequestEmailChange(t.Context(), f.account.Subject.ID, "migration.primary@example.test"))
	before, err := f.runtime.PendingEmailChange(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	_, notice := queuedNotification(t, f.db, f.account.Subject.ID, "email_change")
	var historyBefore, historyAfter string
	query := `SELECT jsonb_agg(to_jsonb(h) ORDER BY version)::text FROM goauth_migration_history h WHERE version<=10`
	require.NoError(t, f.db.QueryRowContext(t.Context(), query).Scan(&historyBefore))
	removeScopedEmailSchema(t, f.db)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), f.db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
	require.NoError(t, f.db.QueryRowContext(t.Context(), query).Scan(&historyAfter))
	require.Equal(t, historyBefore, historyAfter)
	after, err := f.runtime.PendingEmailChange(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	account, err := f.runtime.ConfirmEmailChange(t.Context(), f.account.Subject.ID, notice.Data["code"])
	require.NoError(t, err)
	require.Equal(t, "migration.primary@example.test", account.PrimaryEmail.NormalizedValue)
	target, err := f.target.SnapshotEmailChangeTarget(context.Background(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, "old.alias@example.test", target.NormalizedEmail)
}

func TestScopedEmailMigrationTamperFailsClosed(t *testing.T) {
	for name, query := range map[string]string{
		"constraint": `ALTER TABLE auth_email_change_records DROP CONSTRAINT auth_email_change_scope_snapshot;
   ALTER TABLE auth_email_change_records ADD CONSTRAINT auth_email_change_scope_snapshot CHECK(true)`,
		"default":  `ALTER TABLE auth_email_change_records ALTER COLUMN scope SET DEFAULT 'untrusted'`,
		"nullable": `ALTER TABLE auth_email_change_records ALTER COLUMN scope DROP NOT NULL`,
		"index": `DROP INDEX auth_email_change_scope_pending_idx;
   CREATE INDEX auth_email_change_scope_pending_idx ON auth_email_change_records(subject_id)`,
		"checksum": `UPDATE goauth_migration_history SET checksum='changed' WHERE version=11`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newScopedEmailFixture(t)
			_, err := f.db.ExecContext(t.Context(), query)
			require.NoError(t, err)
			require.Error(t, postgres.VerifySchema(t.Context(), f.db))
			require.Error(t, postgres.Migrate(t.Context(), f.db))
		})
	}
}

func TestScopedEmailConstraintRejectsIncompleteSnapshot(t *testing.T) {
	f := newScopedEmailFixture(t)
	pending, _, _ := f.issue(t, "new.alias@example.test")
	for _, query := range []string{
		"UPDATE auth_email_change_records SET expected_security_version=NULL WHERE id=$1",
		"UPDATE auth_email_change_records SET target_version=NULL WHERE id=$1",
		"UPDATE auth_email_change_records SET old_normalized_value=NULL WHERE id=$1",
	} {
		_, err := f.db.ExecContext(t.Context(), query, pending.ID)
		require.Error(t, err)
	}
	_, err := f.db.ExecContext(t.Context(), `UPDATE auth_email_change_records SET scope='' WHERE id=$1`, pending.ID)
	require.Error(t, err)
	current, err := f.runtime.PendingEmailChange(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, pending, current)
}
