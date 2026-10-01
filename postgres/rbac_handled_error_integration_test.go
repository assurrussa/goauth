//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
)

func TestManagedRBACHandledErrorPreservesOperationState(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Close()) })
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "handled-rbac@example.test", Password: "Integration-Unique-Passphrase-1",
	})
	require.NoError(t, err)
	cache := &managedCachedDenial{}
	permissions, err := runtime.RBAC(cache)
	require.NoError(t, err)
	for _, key := range []rbac.PermissionKey{"users:read", "users:write"} {
		_, err = permissions.UpsertPermission(t.Context(), rbac.Permission{Key: key})
		require.NoError(t, err)
	}
	original, err := permissions.CreateRole(t.Context(), rbac.Role{Slug: "operator", Name: "Operator"}, []rbac.PermissionKey{"users:read"})
	require.NoError(t, err)
	other, err := permissions.CreateRole(t.Context(), rbac.Role{Slug: "other", Name: "Other"}, nil)
	require.NoError(t, err)
	require.NoError(t, permissions.AssignRole(t.Context(), account.Subject.ID, original.Slug))
	_, err = db.ExecContext(t.Context(), `CREATE TABLE host_rbac_progress (step text PRIMARY KEY)`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.WithoutCancel(t.Context()), `DROP TABLE host_rbac_progress`)
		require.NoError(t, err)
	})
	keys := []rbac.PermissionKey{"users:write", "missing:permission"}
	for _, tc := range []struct {
		name  string
		write func(context.Context) error
		want  error
	}{
		{"set permissions", func(ctx context.Context) error { return permissions.SetRolePermissions(ctx, original.Slug, keys) }, rbac.ErrPermissionNotFound},
		{"replace permissions", func(ctx context.Context) error { return permissions.ReplaceRolePermissions(ctx, original.ID, keys) }, rbac.ErrPermissionNotFound},
		{"replace roles", func(ctx context.Context) error {
			return permissions.ReplaceSubjectRoles(ctx, account.Subject.ID, []int64{other.ID, 9223372036854775807})
		}, rbac.ErrRoleNotFound},
		{"create role", func(ctx context.Context) error {
			_, err := permissions.CreateRole(ctx, rbac.Role{Slug: "failed-create", Name: "Failed"}, keys)
			return err
		}, rbac.ErrPermissionNotFound},
		{"update role", func(ctx context.Context) error {
			changed := original
			changed.Name = "Changed"
			_, err := permissions.UpdateRole(ctx, changed, &keys)
			return err
		}, rbac.ErrPermissionNotFound},
		{"SQL error", func(ctx context.Context) error {
			changed := original
			changed.Slug = other.Slug
			_, err := permissions.UpdateRole(ctx, changed, nil)
			return err
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache.calls.Store(0)
			cache.valid.Store(true)
			err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
				writeErr := tc.write(ctx)
				if tc.want != nil {
					require.ErrorIs(t, writeErr, tc.want)
				} else {
					var pgErr *pgconn.PgError
					require.True(t, errors.As(writeErr, &pgErr))
					require.Equal(t, "23505", pgErr.Code)
				}
				// The host handles the operation error and continues using this transaction.
				require.True(t, permissions.Can(ctx, account.Subject.ID, "users:read"))
				require.False(t, permissions.Can(ctx, account.Subject.ID, "users:write"))
				require.True(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"), "a failed write still reserves bypass until outer commit")
				executor, executorErr := runtime.SQLExecutor(ctx)
				if executorErr != nil {
					return executorErr
				}
				_, continuationErr := executor.ExecContext(ctx, `INSERT INTO host_rbac_progress (step) VALUES ($1)`, tc.name)
				return continuationErr
			})
			require.NoError(t, err)
			require.EqualValues(t, 1, cache.calls.Load())
			actual, readErr := permissions.Role(t.Context(), original.ID)
			require.NoError(t, readErr)
			require.Equal(t, original, actual, "failed update must preserve metadata and timestamps")
			roleKeys, readErr := permissions.RolePermissions(t.Context(), original.ID)
			require.NoError(t, readErr)
			require.Len(t, roleKeys, 1)
			require.Equal(t, rbac.PermissionKey("users:read"), roleKeys[0].Key)
			roles, readErr := permissions.SubjectRoles(t.Context(), account.Subject.ID)
			require.NoError(t, readErr)
			require.Len(t, roles, 1)
			require.Equal(t, original.ID, roles[0].ID)
			failed, readErr := permissions.Roles(t.Context(), rbac.RoleFilter{Slugs: []string{"failed-create"}})
			require.NoError(t, readErr)
			require.Empty(t, failed)
			var continued bool
			require.NoError(t, db.QueryRowContext(t.Context(), `SELECT EXISTS (SELECT 1 FROM host_rbac_progress WHERE step=$1)`, tc.name).Scan(&continued))
			require.True(t, continued, "handled operation errors must leave host writes usable")
			require.True(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"))
			require.False(t, permissions.Can(t.Context(), account.Subject.ID, "users:write"))
		})
	}
}
