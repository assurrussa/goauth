package postgres //nolint:testpackage // Pause SQL commit before cache callbacks to test stale-grant rejection.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

type (
	cacheCommitBoundary struct{ committed, release chan struct{} }
	cacheBoundaryDriver struct{ boundary *cacheCommitBoundary }
	cacheBoundaryConn   struct {
		notificationRecordingConn
		boundary *cacheCommitBoundary
	}
)
type cacheBoundaryTx struct{ boundary *cacheCommitBoundary }

func (d cacheBoundaryDriver) Open(string) (driver.Conn, error) {
	return &cacheBoundaryConn{boundary: d.boundary}, nil
}

func (c *cacheBoundaryConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return cacheBoundaryTx{boundary: c.boundary}, nil
}

func (*cacheBoundaryConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "SELECT EXISTS") {
		return &cacheBoundaryRoleRows{value: false}, nil
	}
	return &cacheBoundaryRoleRows{}, nil
}

func (tx cacheBoundaryTx) Commit() error {
	// PostgreSQL can make a commit visible before the client receives its result.
	close(tx.boundary.committed)
	<-tx.boundary.release
	return nil
}

func (cacheBoundaryTx) Rollback() error { return nil }

type cacheBoundaryRoleRows struct {
	read  bool
	value driver.Value
}

func (*cacheBoundaryRoleRows) Columns() []string { return []string{"id"} }
func (*cacheBoundaryRoleRows) Close() error      { return nil }
func (r *cacheBoundaryRoleRows) Next(values []driver.Value) error {
	if r.read {
		return io.EOF
	}
	r.read = true
	values[0] = r.value
	if r.value == nil {
		values[0] = int64(1)
	}
	return nil
}

type revocationCache struct{ valid atomic.Bool }

func (c *revocationCache) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (allowed, found bool, err error) {
	return true, c.valid.Load(), nil
}

func (c *revocationCache) Invalidate(context.Context) error { c.valid.Store(false); return nil }

func TestRBACRevocationBypassesCacheBeforeCommitReturns(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(map[bool]string{false: "standalone", true: "managed"}[managed], func(t *testing.T) {
			boundary := &cacheCommitBoundary{committed: make(chan struct{}), release: make(chan struct{})}
			name := "goauth-cache-boundary-" + uuid.NewString()
			sql.Register(name, cacheBoundaryDriver{boundary: boundary})
			db, err := sql.Open(name, "")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			delegate := &revocationCache{}
			delegate.valid.Store(true)
			cache := &transactionCache{db: db, delegate: delegate, invalidator: delegate}
			management := &rbacStore{db: db, cache: cache}
			// The authoritative committed state denies the permission; the cache
			// still contains the grant until post-commit invalidation can run.
			authoritative := &authoritativePermissionStore{}
			permissions, err := rbac.New(authoritative, cache)
			require.NoError(t, err)
			subject := goauth.NewSubjectID()
			require.True(t, permissions.Can(t.Context(), subject, "users:read"))
			result, done := make(chan error, 1), make(chan struct{})
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(boundary.release) }); <-done })
			go func() {
				defer close(done)
				if managed {
					result <- (&Store{db: db}).InAuthTransaction(t.Context(), func(ctx context.Context) error {
						return management.SetRolePermissions(ctx, "operator", nil)
					})
				} else {
					result <- management.SetRolePermissions(t.Context(), "operator", nil)
				}
			}()
			select {
			case <-boundary.committed:
			case err := <-result:
				t.Fatalf("write returned before the commit barrier: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("write did not reach the commit barrier")
			}
			require.True(t, delegate.valid.Load(), "post-commit invalidation has not run yet")
			require.False(t, permissions.Can(t.Context(), subject, "users:read"), "a committed revocation must bypass the stale grant")
			require.Equal(t, 1, authoritative.calls, "authorization must read authoritative storage")
			release.Do(func() { close(boundary.release) })
			require.NoError(t, <-result)
			require.False(t, permissions.Can(t.Context(), subject, "users:read"))
			require.Zero(t, cache.pending, "all commit guards must be released")
		})
	}
}

func TestManagedRBACCacheGuardReleasedOnPanicAndCancellation(t *testing.T) {
	const panicAbort = "panic"
	for _, abort := range []string{panicAbort, "cancellation"} {
		t.Run(abort, func(t *testing.T) {
			db := openNotificationRecordingDB(t, "abort-cache-guard")
			delegate := &recoveryCache{}
			cache := &transactionCache{db: db, delegate: delegate, invalidator: delegate}
			management := &rbacStore{db: db, cache: cache}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			authorizationCtx := ctx // Independent read without the managed transaction scope.
			write := func() error {
				return (&Store{db: db}).InAuthTransaction(ctx, func(ctx context.Context) error {
					if err := management.AssignRole(ctx, goauth.NewSubjectID(), "operator"); err != nil {
						return err
					}
					_, found, err := cache.HasPermission(authorizationCtx, goauth.NewSubjectID(), "users:read")
					require.NoError(t, err)
					require.False(t, found, "uncommitted writes must publish bypass")
					if abort == panicAbort {
						panic("host callback aborted")
					}
					cancel()
					return ctx.Err()
				})
			}
			if abort == panicAbort {
				require.Panics(t, func() { _ = write() })
			} else {
				require.ErrorIs(t, write(), context.Canceled)
			}
			_, found, err := cache.HasPermission(t.Context(), goauth.NewSubjectID(), "users:read")
			require.NoError(t, err)
			require.True(t, found, "rollback restores the unchanged cache")
			require.Zero(t, cache.pending)
		})
	}
}

func TestManagedRBACRollbackRetainsOtherPendingWrite(t *testing.T) {
	db := openNotificationRecordingDB(t, "overlapping-cache-guards")
	delegate := &recoveryCache{}
	cache := &transactionCache{db: db, delegate: delegate, invalidator: delegate}
	management := &rbacStore{db: db, cache: cache}
	rolledBack := errors.New("host rolled back")
	var ready, release, done [2]chan struct{}
	var results [2]chan error
	var once [2]sync.Once
	for i := range 2 {
		ready[i], release[i], done[i], results[i] = make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
		t.Cleanup(func() { once[i].Do(func() { close(release[i]) }); <-done[i] })
		go func() {
			defer close(done[i])
			results[i] <- (&Store{db: db}).InAuthTransaction(t.Context(), func(ctx context.Context) error {
				if err := management.AssignRole(ctx, goauth.NewSubjectID(), "operator"); err != nil {
					return err
				}
				close(ready[i])
				<-release[i]
				return rolledBack
			})
		}()
		select {
		case <-ready[i]:
		case err := <-results[i]:
			t.Fatalf("write returned before registration: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("write did not register its cache guard")
		}
	}
	for i := range 2 {
		once[i].Do(func() { close(release[i]) })
		require.ErrorIs(t, <-results[i], rolledBack)
		_, found, err := cache.HasPermission(t.Context(), goauth.NewSubjectID(), "users:read")
		require.NoError(t, err)
		require.Equal(t, i == 1, found, "cache resumes only after both write guards are released")
	}
	require.Zero(t, cache.pending)
}
