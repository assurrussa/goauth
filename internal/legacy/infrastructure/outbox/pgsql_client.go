package outbox

import (
	"context"
	"crypto/tls"
	"time"

	pgsql "github.com/assurrussa/outbox/backends/pgsql/storage"
	pgsqlclient "github.com/assurrussa/outbox/backends/pgsql/storage/pgsqlclient"
	pgsqlinit "github.com/assurrussa/outbox/backends/pgsql/storage/pgsqlinit"
	pgsqltrx "github.com/assurrussa/outbox/backends/pgsql/storage/transaction"
)

type (
	PgsqlClient               = pgsqlclient.Client
	PgsqlPoolOptions          = pgsqlclient.PoolOptions
	PgsqlOptPoolOptionsSetter = pgsqlclient.OptPoolOptionsSetter
	PgsqlTrxManager           = pgsqltrx.Manager
)

var (
	ErrPgsqlOption      = pgsqlclient.ErrOption
	ErrRowAlreadyExists = pgsql.ErrRowAlreadyExists
	ErrNoRows           = pgsql.ErrNoRows
)

func ErrorTransform(err error) error {
	return pgsql.ErrorTransform(err)
}

func PgsqlTrxNew(db pgsql.Transactor) *PgsqlTrxManager {
	return pgsqltrx.New(db)
}

func PgsqlNewPool(ctx context.Context, opts PgsqlPoolOptions) (*PgsqlClient, error) {
	return pgsqlclient.NewPool(ctx, opts)
}

func PgsqlCreateDSN(opts PgsqlPoolOptions) (*tls.Config, string, error) {
	return pgsqlclient.CreateDSN(opts)
}

func PgsqlNewOptions(
	address string,
	username string,
	password string,
	database string,
	options ...PgsqlOptPoolOptionsSetter,
) PgsqlPoolOptions {
	return pgsqlclient.NewOptions(address, username, password, database, options...)
}

func PgsqlCreate(
	ctx context.Context,
	dsn string,
	options ...pgsqlclient.OptPoolOptionsSetter,
) (*pgsqlclient.Client, error) {
	return pgsqlinit.Create(ctx, dsn, options...)
}

func PgsqlCreateWithConfig(
	ctx context.Context,
	psqlConf pgsql.PSQLConfig,
	options ...pgsqlclient.OptPoolOptionsSetter,
) (*pgsqlclient.Client, error) {
	return pgsqlinit.CreateWithConfig(ctx, psqlConf, options...)
}

func WithPgsqlTLSConfig(cfg *tls.Config) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithTLSConfig(cfg)
}

func WithPgsqlTLSPath(cert string, key string) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithTLSPath(cert, key)
}

func WithPgsqlLogger(logger Logger) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithLogger(logger)
}

func WithPgsqlDebug(debug bool) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithDebug(debug)
}

func WithPgsqlCheck(check bool) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithCheck(check)
}

func WithPgsqlEnvironment(env string) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithEnvironment(env)
}

func WithPgsqlMaxConnIdleTime(maxConnIdleTime time.Duration) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithMaxConnIdleTime(maxConnIdleTime)
}

func WithPgsqlMaxConnLifeTime(maxConnLifeTime time.Duration) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithMaxConnLifeTime(maxConnLifeTime)
}

func WithPgsqlMaxConnectionsCount(maxConnections int32) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithMaxConnectionsCount(maxConnections)
}

func WithPgsqlMinConnectionsCount(minConnections int32) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithMinConnectionsCount(minConnections)
}

func WithPgsqlSSLMode(sslMode string) PgsqlOptPoolOptionsSetter {
	return pgsqlclient.WithSSLMode(sslMode)
}
