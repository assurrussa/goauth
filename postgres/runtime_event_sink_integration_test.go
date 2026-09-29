//go:build integration

package postgres_test

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/testkit"
)

func TestRuntimeRejectsCustomEventSinkBeforeDatabaseSideEffects(t *testing.T) {
	db := integrationDB(t)
	for _, withSender := range []bool{false, true} {
		name := "without sender"
		if withSender {
			name = "with sender"
		}
		t.Run(name, func(t *testing.T) {
			resetSchema(t, db)
			config := postgres.Config{DB: db, AutoMigrate: true, Runtime: runtimeConfig(t)}
			config.Runtime.EventSink = &testkit.EventSink{}
			if withSender {
				config.NotificationSender = integrationNotificationSender()
			}
			runtime, err := postgres.NewRuntime(config)
			if runtime != nil {
				require.NoError(t, runtime.Close())
			}
			var subjects sql.NullString
			require.NoError(t, db.QueryRow(`SELECT to_regclass('public.auth_subjects')::text`).Scan(&subjects))
			require.EqualError(t, err, "PostgreSQL requires its local encrypted notification queue; "+
				"use direct root Runtime for custom transactional event wiring")
			require.Nil(t, runtime)
			require.False(t, subjects.Valid, "rejected event wiring must not migrate the schema")
		})
	}
}
