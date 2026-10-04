package postgres //nolint:testpackage // Exercise public RBAC calls with the transaction outcome driver.

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

type concurrentInvalidationCache struct {
	calls atomic.Int64
	err   error
}

func (*concurrentInvalidationCache) HasPermission(
	context.Context, goauth.SubjectID, rbac.PermissionKey,
) (allowed, found bool, err error) {
	return true, true, nil
}

func (c *concurrentInvalidationCache) Invalidate(context.Context) error {
	c.calls.Add(1)
	return c.err
}

func TestConcurrentManagedRBACCallbacks(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "joining", true: "owned"}[owned], func(t *testing.T) {
			rollback := errors.New("host rollback")
			for _, tc := range []struct {
				name                                    string
				callbackErr, commitErr, invalidationErr error
				wantErr                                 error
				wantCalls                               int64
				wantAllowed                             bool
			}{
				{name: "commit", wantCalls: 1, wantAllowed: true},
				{name: "rollback", callbackErr: rollback, wantErr: rollback, wantAllowed: true},
				{name: "unknown commit", commitErr: io.ErrUnexpectedEOF, wantErr: goauth.ErrOperationOutcomeUnknown},
				{name: "rejected commit", commitErr: &pgconn.PgError{Code: "40001"}, wantAllowed: true},
				{name: "failed invalidation", invalidationErr: errors.New("cache unavailable"), wantCalls: 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					driverName := "goauth-concurrent-rbac-" + uuid.NewString()
					sql.Register(driverName, commitResultDriver{err: tc.commitErr})
					db, err := sql.Open(driverName, "")
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, db.Close()) })
					store, err := NewStore(db)
					require.NoError(t, err)
					runtime := &Runtime{db: db, store: store}
					cache := &concurrentInvalidationCache{err: tc.invalidationErr}
					permissions, err := runtime.RBAC(cache)
					require.NoError(t, err)
					subject := goauth.NewSubjectID()
					require.True(t, permissions.Can(t.Context(), subject, "users:read"))
					transaction := runtime.InAuthTransaction
					if owned {
						transaction = runtime.InOwnedAuthTransaction
					}
					err = transaction(t.Context(), func(ctx context.Context) error {
						assignConcurrentRoles(t, ctx, permissions, subject)
						require.Zero(t, cache.calls.Load(), "invalidation must wait for durable commit")
						return tc.callbackErr
					})
					switch {
					case tc.wantErr != nil:
						require.ErrorIs(t, err, tc.wantErr)
					case tc.commitErr != nil:
						require.ErrorIs(t, err, tc.commitErr)
						require.NotErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
					default:
						require.NoError(t, err)
					}
					require.Equal(t, tc.wantCalls, cache.calls.Load(), "one invalidation per transaction and cache")
					require.Equal(t, tc.wantAllowed, permissions.Can(t.Context(), subject, "users:read"))
				})
			}
		})
	}
}

func assignConcurrentRoles(t *testing.T, ctx context.Context, permissions *rbac.Service, subject goauth.SubjectID) {
	t.Helper()
	const assignments = 64
	start := make(chan struct{})
	results := make(chan error, assignments)
	var workers sync.WaitGroup
	for range assignments {
		workers.Go(func() {
			<-start
			results <- permissions.AssignRole(ctx, subject, "operator")
		})
	}
	close(start)
	workers.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
}

func TestManagedRBACCoalescesEachCacheSeparately(t *testing.T) {
	db := openNotificationRecordingDB(t, "distinct-managed-caches")
	first, second := &concurrentInvalidationCache{}, &concurrentInvalidationCache{}
	one, err := NewRBAC(db, first)
	require.NoError(t, err)
	two, err := NewRBAC(db, second)
	require.NoError(t, err)
	require.NoError(t, (&Store{db: db}).InAuthTransaction(t.Context(), func(ctx context.Context) error {
		assignConcurrentRoles(t, ctx, one, goauth.NewSubjectID())
		assignConcurrentRoles(t, ctx, two, goauth.NewSubjectID())
		require.Zero(t, first.calls.Load())
		require.Zero(t, second.calls.Load())
		return nil
	}))
	require.EqualValues(t, 1, first.calls.Load())
	require.EqualValues(t, 1, second.calls.Load())
}
