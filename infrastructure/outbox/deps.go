package outbox

import (
	"time"

	pgsql "github.com/assurrussa/outbox/backends/pgsql/storage"
	"github.com/assurrussa/outbox/outbox"
	"github.com/assurrussa/outbox/outbox/logger"
	sharedjob "github.com/assurrussa/outbox/shared/job"
)

type (
	StoragePgsqlFnCallback         = pgsql.FnCallback
	StoragePgsqlClient             = pgsql.Client
	StoragePgsqlDBEngine           = pgsql.DBEngine
	StoragePgsqlTransactor         = pgsql.Transactor
	StoragePgsqlTxManager          = pgsql.TxManager
	StoragePgsqlSqlizer            = pgsql.Sqlizer
	StoragePgsqlPinger             = pgsql.Pinger
	StoragePgsqlNamedExecer        = pgsql.NamedExecer
	StoragePgsqlNamedExecerSqlizer = pgsql.NamedExecerSqlizer
	StoragePgsqlQueryExecer        = pgsql.QueryExecer
	StoragePgsqlQueryExecerSqlizer = pgsql.QueryExecerSqlizer
	StoragePgsqlBatcherExtended    = pgsql.BatcherExtended
	StoragePgsqlSQLExecer          = pgsql.SQLExecer
	StoragePgsqlDBPgxEnginePool    = pgsql.DBPgxEnginePool
	StoragePgsqlConfig             = pgsql.PSQLConfig
)

type (
	Stats                = outbox.Stats
	Job                  = outbox.Job
	Putter               = outbox.Putter
	Transactor           = outbox.Transactor
	JobsRepository       = outbox.JobsRepository
	JobsStatRepository   = outbox.JobsStatRepository
	JobsFailedRepository = outbox.JobsFailedRepository
	Logger               = logger.Logger
)

type (
	Service          = outbox.Service
	OptOptionsSetter = outbox.OptOptionsSetter
	DefaultJob       = sharedjob.DefaultJob
	QueueStats       = outbox.QueueStats
)

func New(options ...OptOptionsSetter) (*Service, error) {
	return outbox.New(options...)
}

func WithWorkers(workers int) OptOptionsSetter {
	return outbox.WithWorkers(workers)
}

func WithIdleTime(idleTime time.Duration) OptOptionsSetter {
	return outbox.WithIdleTime(idleTime)
}

func WithReserveFor(reserveFor time.Duration) OptOptionsSetter {
	return outbox.WithReserveFor(reserveFor)
}

func WithLogger(logger Logger) OptOptionsSetter {
	return outbox.WithLogger(logger)
}

func WithTransactor(transactor Transactor) OptOptionsSetter {
	return outbox.WithTransactor(transactor)
}

func WithJobsRepo(jobsRepo JobsRepository) OptOptionsSetter {
	return outbox.WithJobsRepo(jobsRepo)
}

func WithJobsStatRepo(jobsStatRepo JobsStatRepository) OptOptionsSetter {
	return outbox.WithJobsStatRepo(jobsStatRepo)
}

func WithJobsFailedRepo(jobsFailedRepo JobsFailedRepository) OptOptionsSetter {
	return outbox.WithJobsFailedRepo(jobsFailedRepo)
}
