//nolint:testpackage // Exercises private transaction ownership and cache commit callbacks with the recording driver.
package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

type invalidationCache struct{ calls int }

func (*invalidationCache) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (allowed, found bool, err error) {
	return true, true, nil
}
func (c *invalidationCache) Invalidate(context.Context) error { c.calls++; return nil }

func TestManagedHostExecutorAndCacheCommitBoundary(t *testing.T) {
	db := openNotificationRecordingDB(t, "host")
	store, _ := NewStore(db)
	runtime := &Runtime{db: db, store: store}
	cache := &invalidationCache{}
	management := &rbacStore{db: db, cache: &transactionCache{db: db, delegate: cache, invalidator: cache}}
	rollback := errors.New("rollback projection")
	for _, abort := range []bool{true, false} {
		err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			executor, err := runtime.SQLExecutor(ctx)
			require.NoError(t, err)
			_, owns := executor.(interface{ Commit() error })
			require.False(t, owns)
			_, err = executor.ExecContext(ctx, "projection-write")
			require.NoError(t, err)
			require.NoError(t, management.AssignRole(ctx, goauth.NewSubjectID(), "administrator"))
			require.Zero(t, cache.calls)
			allowed, found, err := management.cache.HasPermission(ctx, goauth.NewSubjectID(), "users:read")
			require.NoError(t, err)
			require.False(t, allowed)
			require.False(t, found)
			if abort {
				return rollback
			}
			return nil
		})
		if abort {
			require.ErrorIs(t, err, rollback)
			require.Zero(t, cache.calls)
		} else {
			require.NoError(t, err)
			require.Equal(t, 1, cache.calls)
		}
	}
	foreign := openNotificationRecordingDB(t, "foreign")
	foreignStore, _ := NewStore(foreign)
	require.NoError(t, foreignStore.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, err := runtime.SQLExecutor(ctx)
		require.ErrorIs(t, err, errForeignNotificationTransaction)
		return nil
	}))
}
