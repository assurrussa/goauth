package migrations

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"testing"
	"time"

	logger "github.com/assurrussa/goshared/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/infrastructure/outbox"
)

func TestMigrationTableNameIsStable(t *testing.T) {
	t.Parallel()

	require.Equal(t, "goauth_goose_db_version", TableName)
}

func TestPublicConfigSurfaceCompiles(t *testing.T) {
	t.Parallel()

	_ = DatabaseConfig{}
	requireRunWithConfigSignature(RunWithConfig)
	requireRunSignature(Run)
}

func requireRunWithConfigSignature(func(context.Context, DatabaseConfig, *sql.DB, string, ...string) error) {
}

func requireRunSignature(func(context.Context, outbox.StoragePgsqlConfig, *sql.DB, string, logger.Logger, ...string) error) {
}

func TestDatabaseConfigDSNNormalizesStorageConfig(t *testing.T) {
	t.Parallel()

	password := strings.Repeat("s", 6)
	cfg, err := storageConfig(DatabaseConfig{
		DSN:                 postgresDSN("goauth", password, "pgsql.local:15432", "goauthdb", "require"),
		MinConnectionsCount: 2,
		MaxConnectionsCount: 7,
		MaxConnIdleTime:     2 * time.Minute,
		MaxConnLifeTime:     30 * time.Minute,
	})
	require.NoError(t, err)

	assert.Equal(t, "pgsql.local:15432", cfg.Address)
	assert.Equal(t, "goauth", cfg.Username)
	assert.Equal(t, password, cfg.Password)
	assert.Equal(t, "goauthdb", cfg.Database)
	assert.Equal(t, "require", cfg.SSLMode)
	assert.Equal(t, int32(2), cfg.MinConnectionsCount)
	assert.Equal(t, int32(7), cfg.MaxConnectionsCount)
	assert.Equal(t, 2*time.Minute, cfg.MaxConnIdleTime)
	assert.Equal(t, 30*time.Minute, cfg.MaxConnLifeTime)
}

func TestDatabaseConfigDSNReportsParseError(t *testing.T) {
	t.Parallel()

	_, err := storageConfig(DatabaseConfig{DSN: "postgres://%zz"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse database dsn")
}

func postgresDSN(username string, password string, host string, database string, sslMode string) string {
	parsed := url.URL{
		Scheme: "postgresql",
		User:   url.UserPassword(username, password),
		Host:   host,
		Path:   database,
	}
	query := parsed.Query()
	query.Set("sslmode", sslMode)
	parsed.RawQuery = query.Encode()

	return parsed.String()
}
