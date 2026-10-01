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

type overlappingRecoveryCache struct {
	failingGrantCache
	block            atomic.Bool
	entered, release chan struct{}
}

func (c *overlappingRecoveryCache) Invalidate(ctx context.Context) error {
	if c.block.Load() {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return c.failingGrantCache.Invalidate(ctx)
}

func TestRBACCacheRecoversAfterConcurrentPostgresRollback(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.Close()) })
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "overlap-recovery@example.test", Password: "Integration-Unique-Passphrase-1",
	})
	require.NoError(t, err)
	cache := &overlappingRecoveryCache{entered: make(chan struct{}), release: make(chan struct{})}
	writer, err := runtime.RBAC(cache)
	require.NoError(t, err)
	reader, err := runtime.RBAC(cache)
	require.NoError(t, err)
	_, err = writer.UpsertPermission(t.Context(), rbac.Permission{Key: "users:read"})
	require.NoError(t, err)
	role, err := writer.CreateRole(t.Context(), rbac.Role{Slug: "operator", Name: "Operator"}, []rbac.PermissionKey{"users:read"})
	require.NoError(t, err)
	require.NoError(t, writer.AssignRole(t.Context(), account.Subject.ID, role.Slug))
	cache.valid.Store(true)
	require.True(t, reader.Can(t.Context(), account.Subject.ID, "users:read"))
	cache.fail.Store(true)
	require.NoError(t, writer.ReplaceRolePermissions(t.Context(), role.ID, nil))
	require.False(t, reader.Can(t.Context(), account.Subject.ID, "users:read"), "failed invalidation must deny the revoked grant")
	reads := cache.reads.Load()
	cache.fail.Store(false)
	cache.block.Store(true)
	recoveryResult, recoveryDone := make(chan error, 1), make(chan struct{})
	var release sync.Once
	go func() {
		defer close(recoveryDone)
		recoveryResult <- runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			return writer.ReplaceRolePermissions(ctx, role.ID, nil)
		})
	}()
	t.Cleanup(func() { release.Do(func() { close(cache.release) }); <-recoveryDone })
	select {
	case <-cache.entered:
	case err := <-recoveryResult:
		t.Fatalf("recovery did not enter invalidation: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("recovery invalidation did not start")
	}
	rejected := errors.New("later RBAC grant rolled back")
	authorizationCtx := t.Context()
	err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		if err := writer.ReplaceRolePermissions(ctx, role.ID, []rbac.PermissionKey{"users:read"}); err != nil {
			return err
		}
		release.Do(func() { close(cache.release) })
		require.NoError(t, <-recoveryResult)
		require.False(t, reader.Can(authorizationCtx, account.Subject.ID, "users:read"), "pending grant must not reach other readers")
		require.Equal(t, reads, cache.reads.Load(), "pending reservation still bypasses the recovered cache")
		return rejected
	})
	require.ErrorIs(t, err, rejected)
	require.False(t, reader.Can(t.Context(), account.Subject.ID, "users:read"), "rollback preserves the committed revocation")
	require.Greater(t, cache.reads.Load(), reads, "rollback must release bypass without another invalidation")
	keys, err := writer.RolePermissions(t.Context(), role.ID)
	require.NoError(t, err)
	require.Empty(t, keys)
}
