//go:build integration

package testsupport

import (
	"context"
	"testing"

	pgsqltests "github.com/assurrussa/outbox/backends/pgsql/tests"

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

type (
	DBHelper       = pgsqltests.DBHelper
	OptionDatabase = pgsqltests.OptionDatabase
)

func WithDatabasePathFilesMigration(path string) OptionDatabase {
	return pgsqltests.WithDatabasePathFilesMigration(path)
}

func PrepareDB(
	ctx context.Context,
	t *testing.T,
	dbName string,
	opts ...OptionDatabase,
) (outbox.StoragePgsqlClient, *DBHelper, func(context.Context)) {
	return pgsqltests.PrepareDB(ctx, t, dbName, opts...)
}
