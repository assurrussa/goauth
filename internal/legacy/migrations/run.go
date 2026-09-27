package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sync"

	logger "github.com/assurrussa/gologger"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver
	"github.com/pressly/goose/v3"

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

const (
	TableName = "goauth_goose_db_version"
	directory = "sql"
)

var gooseMu sync.Mutex

//go:embed sql/*.sql
var files embed.FS

func Run(
	ctx context.Context,
	cfg outbox.StoragePgsqlConfig,
	db *sql.DB,
	command string,
	log logger.Logger,
	args ...string,
) (errReturn error) {
	if log == nil {
		log = logger.Discard()
	}

	if db == nil {
		_, dsn, err := outbox.PgsqlCreateDSN(outbox.PgsqlNewOptions(
			cfg.Address,
			cfg.Username,
			cfg.Password,
			cfg.Database,
			outbox.WithPgsqlSSLMode(cfg.SSLMode),
			outbox.WithPgsqlTLSPath(cfg.TLSCert, cfg.TLSKey),
			outbox.WithPgsqlMinConnectionsCount(cfg.MinConnectionsCount),
			outbox.WithPgsqlMaxConnectionsCount(cfg.MaxConnectionsCount),
			outbox.WithPgsqlMaxConnIdleTime(cfg.MaxConnIdleTime),
			outbox.WithPgsqlMaxConnLifeTime(cfg.MaxConnLifeTime),
			outbox.WithPgsqlDebug(cfg.DebugMode),
		))
		if err != nil {
			return fmt.Errorf("create psql dsn: %w", err)
		}

		db, err = sql.Open("pgx", dsn)
		if err != nil {
			return fmt.Errorf("open database: %w", err)
		}
		defer func() {
			if err := db.Close(); err != nil {
				errReturn = errors.Join(errReturn, fmt.Errorf("close database connection: %w", err))
			}
		}()
	}

	gooseMu.Lock()
	defer gooseMu.Unlock()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("set goose dialect: %w", err)
	}

	prevTableName := goose.TableName()
	goose.SetBaseFS(files)
	goose.SetTableName(TableName)
	defer goose.SetBaseFS(nil)
	defer goose.SetTableName(prevTableName)

	if err := goose.RunWithOptionsContext(ctx, command, db, directory, args); err != nil {
		if errors.Is(err, goose.ErrNoMigrationFiles) {
			log.InfoContext(ctx, "goauth migrations skipped", "command", command, "status", "empty")
			return nil
		}

		return fmt.Errorf("run goauth migrations: %w", err)
	}

	return nil
}
