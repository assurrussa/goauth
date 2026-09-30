//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
)

type failingGrantCache struct {
	fail  atomic.Bool
	valid atomic.Bool
	reads atomic.Int64
}

func (c *failingGrantCache) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (allowed, found bool, err error) {
	c.reads.Add(1)
	return true, c.valid.Load(), nil
}

func (c *failingGrantCache) Invalidate(context.Context) error {
	if c.fail.Load() {
		return errors.New("cache unavailable")
	}
	c.valid.Store(false)
	return nil
}

func TestRBACCacheFailureUsesPostgresAndRecovers(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "rbac.cache@example.test", Password: "Integration-Unique-Passphrase-1",
	})
	require.NoError(t, err)
	cache := &failingGrantCache{}
	permissions, err := runtime.RBAC(cache)
	require.NoError(t, err)
	_, err = permissions.UpsertPermission(t.Context(), rbac.Permission{Key: "users:read"})
	require.NoError(t, err)
	role, err := permissions.CreateRole(t.Context(), rbac.Role{Slug: "operator", Name: "Operator"}, []rbac.PermissionKey{"users:read"})
	require.NoError(t, err)
	require.NoError(t, permissions.AssignRole(t.Context(), account.Subject.ID, "operator"))
	cache.valid.Store(true)
	require.True(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"))
	cache.fail.Store(true)
	require.NoError(t, permissions.ReplaceRolePermissions(t.Context(), role.ID, nil))
	reads := cache.reads.Load()
	require.False(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"), "must not trust cached revoked grant")
	require.NoError(t, permissions.ReplaceRolePermissions(t.Context(), role.ID, []rbac.PermissionKey{"users:read"}))
	require.True(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"), "cache outage must not deny authoritative grants")
	require.Equal(t, reads, cache.reads.Load())
	cache.fail.Store(false)
	require.NoError(t, permissions.ReplaceRolePermissions(t.Context(), role.ID, nil))
	require.False(t, permissions.Can(t.Context(), account.Subject.ID, "users:read"))
	require.Greater(t, cache.reads.Load(), reads, "successful invalidation restores normal cache reads")
}
