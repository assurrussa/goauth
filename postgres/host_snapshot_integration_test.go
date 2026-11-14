//go:build integration

package postgres_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
)

func TestHostProjectionSharesRBACSnapshot(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	_, err := db.ExecContext(t.Context(),
		`CREATE TABLE host_snapshot_test (version integer); INSERT INTO host_snapshot_test VALUES(1)`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `DROP TABLE host_snapshot_test`)
		require.NoError(t, err)
	})
	service, err := postgres.NewRBAC(db, nil)
	require.NoError(t, err)
	_, err = service.UpsertRole(t.Context(), rbac.Role{Slug: "before", Name: "Before"})
	require.NoError(t, err)
	version := 0
	snapshot, err := runtime.AuthorizationSnapshot(t.Context(), func(ctx context.Context, q postgres.SQLExecutor) error {
		require.NoError(t, runtime.InOwnedAuthTransaction(ctx, func(write context.Context) error {
			_, e := service.UpsertRole(write, rbac.Role{Slug: "after", Name: "After"})
			if e != nil {
				return e
			}
			exec, e := runtime.SQLExecutor(write)
			if e != nil {
				return e
			}
			_, e = exec.ExecContext(write, `UPDATE host_snapshot_test SET version=2`)
			return e
		}))
		return q.QueryRowContext(ctx, `SELECT version FROM host_snapshot_test`).Scan(&version)
	})
	require.NoError(t, err)
	require.Equal(t, 1, version)
	require.Len(t, snapshot.Roles, 1)
	snapshot, err = runtime.AuthorizationSnapshot(t.Context(), func(ctx context.Context, q postgres.SQLExecutor) error {
		return q.QueryRowContext(ctx, `SELECT version FROM host_snapshot_test`).Scan(&version)
	})
	require.NoError(t, err)
	require.Equal(t, 2, version)
	require.Len(t, snapshot.Roles, 2)
}
