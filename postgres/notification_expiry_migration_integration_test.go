//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

// Start with the actual immutable schema-4 files, rather than downgrading a
// current fixture's marker and accidentally retaining the new index.
func notificationExpiryV4(t *testing.T, db *sql.DB) {
	t.Helper()
	resetSchema(t, db)
	for _, step := range []struct {
		file    string
		version int
	}{
		{"00001_v0_2_baseline.sql", 2}, {"00002_notifications.sql", 3}, {"00003_local_identity.sql", 4},
	} {
		data, err := os.ReadFile("migrations/" + step.file)
		require.NoError(t, err)
		_, err = db.ExecContext(t.Context(), string(data))
		require.NoError(t, err)
		if step.version > 2 {
			checksum := sha256.Sum256(data)
			_, err = db.ExecContext(t.Context(), `INSERT INTO goauth_migration_history(version,checksum) VALUES($1,$2)`, step.version, hex.EncodeToString(checksum[:]))
			require.NoError(t, err)
			_, err = db.ExecContext(t.Context(), `INSERT INTO goauth_schema_version(version) VALUES($1)`, step.version)
			require.NoError(t, err)
		}
	}
}

func TestNotificationExpiryIndexUpgradesV4AndBoundsSelection(t *testing.T) {
	db := integrationDB(t)
	notificationExpiryV4(t, db)
	now := time.Now().UTC()
	const subject = "714a7aa0-113f-45db-86f2-842d62829e70"
	_, err := db.ExecContext(t.Context(), `INSERT INTO auth_subjects VALUES($1,'active',1,$2,$2)`, subject, now)
	require.NoError(t, err)
	// Large retained completed history must not dominate each small live batch.
	_, err = db.ExecContext(t.Context(), `INSERT INTO auth_notification_deliveries
 (id,subject_id,event_type,valid_until,key_id,nonce,ciphertext,additional_data,created_at,delete_after,state,next_attempt_at)
 SELECT md5(i::text)::uuid,$1,'fixture',CASE WHEN i<=30100 THEN $2::timestamptz-interval '1 minute' ELSE $2::timestamptz+interval '1 hour' END,
 'synthetic','\x01',CASE WHEN i<=30000 THEN NULL ELSE '\x01'::bytea END,'\x01',$2,$2::timestamptz+interval '1 day',
 CASE WHEN i<=30000 THEN 'delivered' ELSE 'pending' END,$2 FROM generate_series(1,35000) i`, subject, now)
	require.NoError(t, err)
	var before string
	require.NoError(t, db.QueryRow(`SELECT md5(string_agg(row_to_json(n)::text,'' ORDER BY id)) FROM auth_notification_deliveries n`).Scan(&before))
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, postgres.VerifySchema(t.Context(), db))
	var after string
	require.NoError(t, db.QueryRow(`SELECT md5(string_agg(row_to_json(n)::text,'' ORDER BY id)) FROM auth_notification_deliveries n`).Scan(&after))
	require.Equal(t, before, after, "migration must not rewrite retained notification data")
	_, err = db.Exec(`ANALYZE auth_notification_deliveries`)
	require.NoError(t, err)
	locked, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = locked.Rollback() }()
	_, err = locked.Exec(`SELECT id FROM auth_notification_deliveries WHERE ciphertext IS NOT NULL AND valid_until <= $1 ORDER BY valid_until,id LIMIT 2 FOR UPDATE`, now)
	require.NoError(t, err)
	rows, err := db.QueryContext(t.Context(), `EXPLAIN (ANALYZE, BUFFERS) WITH expired AS (
 SELECT id FROM auth_notification_deliveries WHERE ciphertext IS NOT NULL AND valid_until <= $1
 ORDER BY valid_until,id FOR UPDATE SKIP LOCKED LIMIT $2)
 SELECT count(*) FROM expired`, now, 10)
	require.NoError(t, err)
	plan := expiryPlan(t, rows)
	require.Contains(t, plan, "Index Scan using auth_notification_deliveries_expiry_idx")
	require.NotContains(t, plan, "Sort")
	require.NotContains(t, plan, "Seq Scan")
	config := runtimeConfig(t)
	config.Now = func() time.Time { return now }
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config, NotificationSender: integrationNotificationSender()})
	require.NoError(t, err)
	defer runtime.Close()
	count, err := runtime.ExpireNotifications(t.Context(), 10)
	require.NoError(t, err)
	require.EqualValues(t, 10, count)
	require.NoError(t, locked.Rollback())
	_, err = db.Exec(`UPDATE auth_notification_deliveries SET delete_after=valid_until-interval '1 second' WHERE id=md5('35000')::uuid`)
	require.Error(t, err, "validated deadline order must forbid earlier retention")
	// Same name but wrong key order cannot pass preflight.
	_, err = db.Exec(`DROP INDEX auth_notification_deliveries_expiry_idx; CREATE INDEX auth_notification_deliveries_expiry_idx ON auth_notification_deliveries(id,valid_until) WHERE ciphertext IS NOT NULL`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
}

func expiryPlan(t *testing.T, rows *sql.Rows) string {
	t.Helper()
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	require.NoError(t, rows.Err())
	return plan.String()
}

func TestNotificationExpiryMigrationFailurePreservesV4(t *testing.T) {
	db := integrationDB(t)
	notificationExpiryV4(t, db)
	_, err := db.Exec(`CREATE TABLE auth_notification_deliveries_expiry_idx(id integer)`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := db.ExecContext(context.Background(), `DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_class WHERE relname='auth_notification_deliveries_expiry_idx' AND relkind='r') THEN DROP TABLE auth_notification_deliveries_expiry_idx; END IF; END $$`)
		require.NoError(t, cleanupErr)
	})
	require.Error(t, postgres.Migrate(t.Context(), db))
	var version, history int
	require.NoError(t, db.QueryRow(`SELECT max(version) FROM goauth_schema_version`).Scan(&version))
	require.Equal(t, 4, version)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM goauth_migration_history WHERE version=5`).Scan(&history))
	require.Zero(t, history)
	_, err = db.Exec(`DROP TABLE auth_notification_deliveries_expiry_idx`)
	require.NoError(t, err)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	var constraint string
	require.NoError(t, db.QueryRow(`SELECT conname FROM pg_constraint WHERE conrelid='auth_notification_deliveries'::regclass
 AND pg_get_constraintdef(oid)='CHECK ((valid_until <= delete_after))'`).Scan(&constraint))
	_, err = db.Exec(fmt.Sprintf(`ALTER TABLE auth_notification_deliveries DROP CONSTRAINT %q`, constraint))
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), db), postgres.ErrSchemaNeedsMigration)
}
