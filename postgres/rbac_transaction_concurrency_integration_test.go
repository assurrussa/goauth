//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
)

type managedCachedDenial struct {
	valid atomic.Bool
	calls atomic.Int64
}

func (c *managedCachedDenial) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (allowed, found bool, err error) {
	return false, c.valid.Load(), nil
}

func (c *managedCachedDenial) Invalidate(context.Context) error {
	c.valid.Store(false)
	c.calls.Add(1)
	return nil
}

func TestConcurrentManagedRBACCachePostgresCommitBoundary(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Close()) })
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "parallel-rbac@example.test", Password: "Integration-Unique-Passphrase-1",
	})
	require.NoError(t, err)
	cache := &managedCachedDenial{}
	permissions, err := runtime.RBAC(cache)
	require.NoError(t, err)
	_, err = permissions.UpsertPermission(t.Context(), rbac.Permission{Key: "users:read"})
	require.NoError(t, err)
	_, err = permissions.CreateRole(t.Context(), rbac.Role{Slug: "operator", Name: "Operator"}, []rbac.PermissionKey{"users:read"})
	require.NoError(t, err)
	cache.calls.Store(0)
	cache.valid.Store(true)
	require.False(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"))
	rejection := errors.New("host projection rejected")
	for _, abort := range []bool{true, false} {
		err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			assignParallelPostgresRoles(t, ctx, permissions, account.Subject.ID)
			require.Zero(t, cache.calls.Load(), "no invalidation before durable commit")
			require.True(t, permissions.Can(ctx, account.Subject.ID, "users:read"), "managed reads bypass stale cache")
			if abort {
				return rejection
			}
			return nil
		})
		roles, readErr := permissions.SubjectRoles(t.Context(), account.Subject.ID)
		require.NoError(t, readErr)
		if abort {
			require.ErrorIs(t, err, rejection)
			require.Empty(t, roles)
			require.Zero(t, cache.calls.Load())
			require.False(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"))
		} else {
			require.NoError(t, err)
			require.Len(t, roles, 1)
			require.EqualValues(t, 1, cache.calls.Load(), "parallel writes share one invalidation")
			require.True(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"))
		}
	}
	assertIdempotentRoleAssignment(t, runtime, permissions, account.Subject.ID)
}

func assignParallelPostgresRoles(t *testing.T, ctx context.Context, permissions *rbac.Service, subject goauth.SubjectID) {
	t.Helper()
	start := make(chan struct{})
	results := make(chan error, 64)
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() { <-start; results <- permissions.AssignRole(ctx, subject, "operator") })
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
}

func assertIdempotentRoleAssignment(t *testing.T, runtime *postgres.Runtime, permissions *rbac.Service, subject goauth.SubjectID) {
	t.Helper()
	var before, after time.Time
	const query = "SELECT created_at FROM auth_subject_roles WHERE subject_id=$1"
	require.NoError(t, runtime.Database().QueryRowContext(t.Context(), query, subject).Scan(&before))
	require.NoError(t, permissions.AssignRole(t.Context(), subject, "operator"))
	require.NoError(t, runtime.Database().QueryRowContext(t.Context(), query, subject).Scan(&after))
	require.Equal(t, before, after, "idempotent assignment preserves its original creation time")
	require.ErrorContains(t, permissions.AssignRole(t.Context(), subject, "missing-role"), "RBAC role not found")
	roles, err := permissions.SubjectRoles(t.Context(), subject)
	require.NoError(t, err)
	require.Len(t, roles, 1, "missing role must not change existing assignments")
}
