package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	logger "github.com/assurrussa/goshared/pkg/logger"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/assurrussa/goauth/infrastructure/outbox"
)

// DatabaseConfig is the stable public PostgreSQL config accepted by goauth migrations.
type DatabaseConfig struct {
	DSN                 string
	Address             string
	Username            string
	Password            string
	Database            string
	SSLMode             string
	DebugMode           bool
	MinConnectionsCount int32
	MaxConnectionsCount int32
	TLSCert             string
	TLSKey              string
	MaxConnIdleTime     time.Duration
	MaxConnLifeTime     time.Duration
}

// RunWithConfig executes goauth migrations without requiring callers to import
// goauth internal infrastructure packages.
func RunWithConfig(
	ctx context.Context,
	cfg DatabaseConfig,
	db *sql.DB,
	command string,
	args ...string,
) error {
	storageCfg, err := storageConfig(cfg)
	if err != nil {
		return err
	}

	return Run(ctx, storageCfg, db, command, logger.Discard(), args...)
}

func storageConfig(cfg DatabaseConfig) (outbox.StoragePgsqlConfig, error) {
	cfg, err := normalizeDatabaseConfig(cfg)
	if err != nil {
		return outbox.StoragePgsqlConfig{}, err
	}

	return outbox.StoragePgsqlConfig{
		Address:             cfg.Address,
		Username:            cfg.Username,
		Password:            cfg.Password,
		Database:            cfg.Database,
		SSLMode:             cfg.SSLMode,
		DebugMode:           cfg.DebugMode,
		MinConnectionsCount: cfg.MinConnectionsCount,
		MaxConnectionsCount: cfg.MaxConnectionsCount,
		TLSCert:             cfg.TLSCert,
		TLSKey:              cfg.TLSKey,
		MaxConnIdleTime:     cfg.MaxConnIdleTime,
		MaxConnLifeTime:     cfg.MaxConnLifeTime,
	}, nil
}

func normalizeDatabaseConfig(cfg DatabaseConfig) (DatabaseConfig, error) {
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return cfg, nil
	}

	parsed, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return cfg, fmt.Errorf("parse database dsn: %w", err)
	}

	conn := parsed.ConnConfig
	if conn.Host != "" {
		cfg.Address = conn.Host
		if conn.Port > 0 && !strings.Contains(conn.Host, "/") {
			cfg.Address = net.JoinHostPort(conn.Host, strconv.Itoa(int(conn.Port)))
		}
	}
	if conn.User != "" {
		cfg.Username = conn.User
	}
	if conn.Password != "" {
		cfg.Password = conn.Password
	}
	if conn.Database != "" {
		cfg.Database = conn.Database
	}
	if sslMode := dsnSSLMode(dsn); sslMode != "" {
		cfg.SSLMode = sslMode
	}

	return cfg, nil
}

func dsnSSLMode(dsn string) string {
	parsed, err := url.Parse(dsn)
	if err == nil {
		if sslMode := strings.TrimSpace(parsed.Query().Get("sslmode")); sslMode != "" {
			return sslMode
		}
	}

	for _, field := range strings.Fields(dsn) {
		key, value, ok := strings.Cut(field, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "sslmode") {
			return strings.Trim(strings.TrimSpace(value), "'\"")
		}
	}

	return ""
}
