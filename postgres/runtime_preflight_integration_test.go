//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/testkit"
)

func TestInvalidRuntimeConfigDoesNotMigrateSchema(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	ctx := context.Background()
	require.NoError(t, postgres.Migrate(ctx, db))
	_, err := db.ExecContext(ctx, `
DROP TABLE auth_notification_deliveries;
DROP TABLE goauth_migration_history;
DELETE FROM goauth_schema_version WHERE version >= 3;
ALTER TABLE auth_subjects DROP COLUMN retired_at;
ALTER TABLE auth_local_credentials DROP COLUMN password_input_policy;`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.VerifySchema(ctx, db), postgres.ErrSchemaNeedsMigration)

	for _, test := range []struct {
		name      string
		mutate    func(*postgres.Config)
		wantError string
	}{
		{
			name: "sender and custom event sink",
			mutate: func(config *postgres.Config) {
				config.Runtime.EventSink = &testkit.EventSink{}
			},
			wantError: "PostgreSQL requires its local encrypted notification queue",
		},
		{
			name: "invalid worker settings",
			mutate: func(config *postgres.Config) {
				config.NotificationWorker.MaxAttempts = -1
			},
			wantError: "invalid notification worker configuration",
		},
		{
			name: "missing reset URL builder",
			mutate: func(config *postgres.Config) {
				config.Runtime.URLBuilder = nil
			},
			wantError: goauth.ErrURLBuilderRequired.Error(),
		},
		{
			name: "missing token key",
			mutate: func(config *postgres.Config) {
				config.Runtime.TokenHMACKeys = goauth.KeyRing{}
			},
			wantError: goauth.ErrKeyRingInvalid.Error(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := postgres.Config{
				DB: db, AutoMigrate: true, Runtime: runtimeConfig(t),
				NotificationSender: integrationNotificationSender(),
			}
			test.mutate(&config)
			_, err := postgres.NewRuntime(config)
			require.ErrorContains(t, err, test.wantError)
			require.ErrorIs(t, postgres.VerifySchema(ctx, db), postgres.ErrSchemaNeedsMigration)
			var version int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT max(version) FROM goauth_schema_version`).Scan(&version))
			require.Equal(t, 2, version)
		})
	}
}
