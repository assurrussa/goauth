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

func removeNotificationSenderDiagnosticsSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `ALTER TABLE auth_notification_deliveries
 DROP COLUMN last_sender_outcome, DROP COLUMN last_sender_code, DROP COLUMN last_sender_http_status,
 DROP COLUMN last_sender_attempt, DROP COLUMN last_sender_observed_at;
DELETE FROM goauth_migration_history WHERE version=13;
DELETE FROM goauth_schema_version WHERE version=13;`)
	require.NoError(t, err)
}

func notificationPreSenderSnapshot(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var snapshot string
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT (to_jsonb(n)-'last_sender_outcome'-'last_sender_code'
 -'last_sender_http_status'-'last_sender_attempt'-'last_sender_observed_at')::text
FROM auth_notification_deliveries n WHERE id=$1`, id).Scan(&snapshot))
	return snapshot
}

func TestNotificationSenderDiagnosticsMigrationPreservesLegacyRowsAndHistory(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	ids := []string{f.insert(t, "pending", f.now.Add(time.Hour), 2, false), f.insert(t, "exhausted", f.now.Add(-time.Hour), 10, true)}
	removeNotificationSenderDiagnosticsSchema(t, f.db)
	before := make([]string, len(ids))
	for i, id := range ids {
		before[i] = notificationPreSenderSnapshot(t, f.db, id)
	}
	var historyBefore, historyAfter string
	const history = `SELECT jsonb_agg(to_jsonb(h) ORDER BY version)::text FROM goauth_migration_history h WHERE version<=12`
	require.NoError(t, f.db.QueryRowContext(t.Context(), history).Scan(&historyBefore))
	require.ErrorIs(t, postgres.VerifySchema(t.Context(), f.db), postgres.ErrSchemaNeedsMigration)
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
	require.NoError(t, postgres.VerifySchema(t.Context(), f.db))
	for i, id := range ids {
		require.Equal(t, before[i], notificationPreSenderSnapshot(t, f.db, id))
		var empty bool
		require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT last_sender_outcome IS NULL AND last_sender_code IS NULL
   AND last_sender_http_status IS NULL AND last_sender_attempt IS NULL AND last_sender_observed_at IS NULL
   FROM auth_notification_deliveries WHERE id=$1`, id).Scan(&empty))
		require.True(t, empty, "legacy diagnostics must not be fabricated")
	}
	require.NoError(t, f.db.QueryRowContext(t.Context(), history).Scan(&historyAfter))
	require.Equal(t, historyBefore, historyAfter)
	data, err := os.ReadFile("migrations/00012_notification_sender_diagnostics.sql")
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	var recorded string
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT checksum FROM goauth_migration_history WHERE version=13`).Scan(&recorded))
	require.Equal(t, hex.EncodeToString(sum[:]), recorded)
}

func TestNotificationSenderDiagnosticsMigrationFailureRollsBack(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	removeNotificationSenderDiagnosticsSchema(t, f.db)
	_, err := f.db.ExecContext(t.Context(), `ALTER TABLE auth_notification_deliveries ADD COLUMN last_sender_outcome text`)
	require.NoError(t, err)
	require.Error(t, postgres.Migrate(t.Context(), f.db))
	var version, history, columns int
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT max(version) FROM goauth_schema_version`).Scan(&version))
	require.Equal(t, 12, version)
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM goauth_migration_history WHERE version=13`).Scan(&history))
	require.Zero(t, history)
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_schema='public'
 AND table_name='auth_notification_deliveries' AND column_name='last_sender_code'`).Scan(&columns))
	require.Zero(t, columns)
	_, err = f.db.ExecContext(t.Context(), `ALTER TABLE auth_notification_deliveries DROP COLUMN last_sender_outcome`)
	require.NoError(t, err)
	require.NoError(t, postgres.Migrate(t.Context(), f.db))
}

func TestNotificationSenderDiagnosticsMigrationRejectsTampering(t *testing.T) {
	mutations := map[string]string{
		"missing column":      `ALTER TABLE auth_notification_deliveries DROP COLUMN last_sender_observed_at`,
		"outcome length":      `ALTER TABLE auth_notification_deliveries ALTER COLUMN last_sender_outcome TYPE varchar(33)`,
		"code length":         `ALTER TABLE auth_notification_deliveries ALTER COLUMN last_sender_code TYPE varchar(65)`,
		"status type":         `ALTER TABLE auth_notification_deliveries ALTER COLUMN last_sender_http_status TYPE bigint`,
		"attempt type":        `ALTER TABLE auth_notification_deliveries ALTER COLUMN last_sender_attempt TYPE bigint`,
		"timestamp precision": `ALTER TABLE auth_notification_deliveries ALTER COLUMN last_sender_observed_at TYPE timestamptz(3)`,
		"checksum":            `UPDATE goauth_migration_history SET checksum='tampered' WHERE version=13`,
	}
	for _, column := range []string{"outcome", "code", "http_status", "attempt", "observed_at"} {
		name := "last_sender_" + column
		mutations[name+" nullability"] = "ALTER TABLE auth_notification_deliveries ALTER COLUMN " + name + " SET NOT NULL"
		value := "1"
		if column == "outcome" {
			value = "'unknown'"
		}
		if column == "code" {
			value = "'unknown'"
		}
		if column == "observed_at" {
			value = "CURRENT_TIMESTAMP"
		}
		mutations[name+" default"] = "ALTER TABLE auth_notification_deliveries ALTER COLUMN " + name + " SET DEFAULT " + value
	}
	for _, name := range []string{"outcome", "code", "http", "attempt", "snapshot"} {
		constraint := "auth_notification_sender_" + name + "_check"
		drop := "ALTER TABLE auth_notification_deliveries DROP CONSTRAINT " + constraint
		mutations[name+" missing constraint"] = drop
		mutations[name+" weakened constraint"] = drop + "; ALTER TABLE auth_notification_deliveries ADD CONSTRAINT " + constraint + " CHECK(true)"
	}
	mutations["unvalidated constraint"] = `ALTER TABLE auth_notification_deliveries DROP CONSTRAINT auth_notification_sender_http_check;
 ALTER TABLE auth_notification_deliveries ADD CONSTRAINT auth_notification_sender_http_check CHECK(last_sender_http_status BETWEEN 100 AND 599) NOT VALID`
	for name, query := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newNotificationLifecycleFixture(t)
			_, err := f.db.ExecContext(t.Context(), query)
			require.NoError(t, err)
			require.Error(t, postgres.VerifySchema(t.Context(), f.db))
			require.Error(t, postgres.Migrate(t.Context(), f.db))
		})
	}
}

func TestNotificationSenderDiagnosticsRejectsUnsafeOrPartialValues(t *testing.T) {
	f := newNotificationLifecycleFixture(t)
	id := f.insert(t, "pending", f.now.Add(time.Hour), 2, false)
	const complete = `UPDATE auth_notification_deliveries SET last_sender_outcome=$2,last_sender_code=$3,
 last_sender_http_status=$4,last_sender_attempt=$5,last_sender_observed_at=$6 WHERE id=$1`
	for _, tc := range []struct {
		name            string
		outcome, code   any
		status, attempt any
		observed        any
	}{
		{"arbitrary outcome", "customer@example.test", "unknown", nil, 1, f.now},
		{"arbitrary code", "unknown", "provider body or token", nil, 1, f.now},
		{"status too low", "unknown", "unknown", 99, 1, f.now},
		{"status too high", "unknown", "unknown", 600, 1, f.now},
		{"zero attempt", "unknown", "unknown", nil, 0, f.now},
		{"future attempt", "unknown", "unknown", nil, 3, f.now},
		{"missing outcome", nil, "unknown", nil, 1, f.now},
		{"missing code", "unknown", nil, nil, 1, f.now},
		{"missing attempt", "unknown", "unknown", nil, nil, f.now},
		{"missing time", "unknown", "unknown", nil, 1, nil},
		{"orphan status", nil, nil, 503, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.db.ExecContext(t.Context(), complete, id, tc.outcome, tc.code, tc.status, tc.attempt, tc.observed)
			require.Error(t, err)
		})
	}
	for _, status := range []any{nil, 100, 599} {
		_, err := f.db.ExecContext(t.Context(), complete, id, "unknown", "unknown", status, 2, f.now)
		require.NoError(t, err)
	}
	_, err := f.db.ExecContext(t.Context(), complete, id, nil, nil, nil, nil, nil)
	require.NoError(t, err)
}
