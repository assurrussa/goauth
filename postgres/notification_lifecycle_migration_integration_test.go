//go:build integration

package postgres_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

// Downgrade only isolated fixtures; older migration tests remove later schemas
// in reverse order so their recorded versions describe the actual schema.
func removeNotificationLifecycleSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `
DROP INDEX auth_notification_deliveries_receipt_cleanup_idx;
ALTER TABLE auth_notification_deliveries
 DROP CONSTRAINT auth_notification_deliveries_state_check,
 ADD CONSTRAINT auth_notification_deliveries_state_check
 CHECK (state IN ('pending','leased','blocked','delivered','exhausted','expired'));
DELETE FROM goauth_migration_history WHERE version=12;
DELETE FROM goauth_schema_version WHERE version=12;`)
	require.NoError(t, err)
}

func TestNotificationLifecycleMigrationPreservesReceiptsAndHistory(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	id := f.insert(t, "pending", f.now.Add(time.Hour), 2, false)
	oldID := f.insert(t, "exhausted", f.now.Add(-24*time.Hour), 10, true)
	removeNotificationLifecycleSchema(t, f.db)
	before := notificationLifecycleSnapshot(t, f.db, id)
	oldBefore := notificationLifecycleSnapshot(t, f.db, oldID)
	var historyBefore, historyAfter string
	const history = "SELECT jsonb_agg(to_jsonb(h) ORDER BY version)::text FROM goauth_migration_history h WHERE version<=11"
	require.NoError(t, f.db.QueryRowContext(t.Context(), history).Scan(&historyBefore))
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), f.db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
	require.NoError(t, postgres.VerifySchema(t.Context(), f.db))
	require.Equal(t, before, notificationLifecycleSnapshot(t, f.db, id))
	require.Equal(t, oldBefore, notificationLifecycleSnapshot(t, f.db, oldID))
	require.NoError(t, f.db.QueryRowContext(t.Context(), history).Scan(&historyAfter))
	require.Equal(t, historyBefore, historyAfter)
	data, err := os.ReadFile("migrations/00011_notification_lifecycle.sql")
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	var recorded string
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT checksum FROM goauth_migration_history WHERE version=12").Scan(&recorded))
	require.Equal(t, hex.EncodeToString(sum[:]), recorded)
	changed, err := f.runtime.CancelNotification(t.Context(), id)
	require.NoError(t, err)
	require.True(t, changed)
}

func TestNotificationLifecycleMigrationRejectsTampering(t *testing.T) {
	for name, query := range map[string]string{
		"missing constraint": "ALTER TABLE auth_notification_deliveries DROP CONSTRAINT auth_notification_deliveries_state_check",
		"weakened constraint": `ALTER TABLE auth_notification_deliveries DROP CONSTRAINT auth_notification_deliveries_state_check;
ALTER TABLE auth_notification_deliveries ADD CONSTRAINT auth_notification_deliveries_state_check CHECK(true)`,
		"unvalidated constraint": `ALTER TABLE auth_notification_deliveries DROP CONSTRAINT auth_notification_deliveries_state_check;
ALTER TABLE auth_notification_deliveries ADD CONSTRAINT auth_notification_deliveries_state_check
CHECK(state IN ('pending','leased','blocked','delivered','exhausted','expired','cancelled')) NOT VALID`,
		"missing index": "DROP INDEX auth_notification_deliveries_receipt_cleanup_idx",
		"weakened index": "DROP INDEX auth_notification_deliveries_receipt_cleanup_idx; " +
			"CREATE INDEX auth_notification_deliveries_receipt_cleanup_idx ON auth_notification_deliveries(id)",
		"checksum": "UPDATE goauth_migration_history SET checksum='tampered' WHERE version=12",
	} {
		t.Run(name, func(t *testing.T) {
			f := newNotificationLifecycleFixture(t)
			_, err := f.db.ExecContext(t.Context(), query)
			require.NoError(t, err)
			require.Error(t, postgres.VerifySchema(t.Context(), f.db))
			require.Error(t, postgres.Migrate(t.Context(), f.db))
		})
	}
}

func TestNotificationLifecycleMigrationFailureRollsBackVersion(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	removeNotificationLifecycleSchema(t, f.db)
	_, err := f.db.ExecContext(t.Context(),
		"ALTER TABLE auth_notification_deliveries RENAME CONSTRAINT auth_notification_deliveries_state_check TO fixture_state_check")
	require.NoError(t, err)
	require.Error(t, postgres.Migrate(t.Context(), f.db))
	var version, history int
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT max(version) FROM goauth_schema_version").Scan(&version))
	require.Equal(t, 11, version)
	require.NoError(t, f.db.QueryRowContext(t.Context(),
		"SELECT count(*) FROM goauth_migration_history WHERE version=12").Scan(&history))
	require.Zero(t, history)
	_, err = f.db.ExecContext(t.Context(),
		"ALTER TABLE auth_notification_deliveries RENAME CONSTRAINT fixture_state_check TO auth_notification_deliveries_state_check")
	require.NoError(t, err)
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
}

func TestNotificationReceiptCleanupIndexSupportsBoundedSelection(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	cutoff := f.now.Add(-7 * 24 * time.Hour)
	_, err := f.db.ExecContext(t.Context(), `
INSERT INTO auth_notification_deliveries
(id,subject_id,event_type,valid_until,key_id,nonce,ciphertext,additional_data,
 created_at,delete_after,state,next_attempt_at)
SELECT md5('lifecycle-plan-' || i::text)::uuid,$1,'fixture',
 CASE WHEN i<=30100 THEN $2::timestamptz-interval '1 minute' ELSE $2::timestamptz+interval '1 hour' END,
 'fixture','\x'::bytea,CASE WHEN i<=30000 THEN '\x01'::bytea ELSE NULL END,'\x'::bytea,$2,
 $2::timestamptz+interval '1 day',CASE WHEN i<=30000 THEN 'pending' ELSE 'expired' END,$2
FROM generate_series(1,35000) i`, f.subject, cutoff)
	require.NoError(t, err)
	_, err = f.db.ExecContext(t.Context(), "ANALYZE auth_notification_deliveries")
	require.NoError(t, err)
	rows, err := f.db.QueryContext(t.Context(), `
EXPLAIN (ANALYZE, BUFFERS)
SELECT id FROM auth_notification_deliveries
WHERE state IN ('delivered','exhausted','expired','cancelled')
 AND ciphertext IS NULL AND octet_length(nonce)=0 AND octet_length(additional_data)=0
 AND lease_token IS NULL AND leased_until IS NULL
 AND GREATEST(COALESCE(delivered_at,valid_until),valid_until)<$1
ORDER BY GREATEST(COALESCE(delivered_at,valid_until),valid_until),id
LIMIT 10 FOR UPDATE SKIP LOCKED`, cutoff)
	require.NoError(t, err)
	plan := expiryPlan(t, rows)
	require.Contains(t, plan, "Index Scan using auth_notification_deliveries_receipt_cleanup_idx")
	require.NotContains(t, plan, "Seq Scan")
	require.NotContains(t, plan, "Sort")
	count, err := f.runtime.CleanupNotificationReceipts(t.Context(), 0, 10)
	require.NoError(t, err)
	require.EqualValues(t, 10, count)
}
