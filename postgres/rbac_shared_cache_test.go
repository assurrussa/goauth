package postgres //nolint:testpackage // Reuse the SQL commit barrier to test separate public RBAC assemblies.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
	"weak"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

const (
	sharedUnknownOutcome      = "unknown outcome"
	sharedInvalidationFailure = "invalidation failure"
	sharedComparableValue     = "comparable value"
)

func TestSharedRBACCacheRevocationAcrossServices(t *testing.T) {
	for _, factory := range []string{"NewRBAC", "Runtime.RBAC"} {
		for _, managed := range []bool{false, true} {
			t.Run(factory+map[bool]string{false: "/standalone", true: "/managed"}[managed], func(t *testing.T) {
				boundary := &cacheCommitBoundary{committed: make(chan struct{}), release: make(chan struct{})}
				name := "goauth-shared-cache-boundary-" + uuid.NewString()
				sql.Register(name, cacheBoundaryDriver{boundary: boundary})
				db, err := sql.Open(name, "")
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, db.Close()) })
				runtime := &Runtime{db: db, store: &Store{db: db}}
				delegate := &revocationCache{}
				delegate.valid.Store(true)
				assemble := func() (*rbac.Service, error) {
					if factory == "NewRBAC" {
						return NewRBAC(db, delegate)
					}
					return runtime.RBAC(delegate)
				}
				writer, err := assemble()
				require.NoError(t, err)
				reader, err := assemble()
				require.NoError(t, err)
				subject := goauth.NewSubjectID()
				require.True(t, reader.Can(t.Context(), subject, "users:read"))
				result, done := make(chan error, 1), make(chan struct{})
				var release sync.Once
				t.Cleanup(func() { release.Do(func() { close(boundary.release) }); <-done })
				go func() {
					defer close(done)
					if managed {
						result <- runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
							return writer.SetRolePermissions(ctx, "operator", nil)
						})
					} else {
						result <- writer.SetRolePermissions(t.Context(), "operator", nil)
					}
				}()
				select {
				case <-boundary.committed:
				case err := <-result:
					t.Fatalf("write did not reach commit barrier: %v", err)
				case <-time.After(5 * time.Second):
					t.Fatal("commit barrier not reached")
				}
				require.True(t, delegate.valid.Load(), "the shared delegate has not been invalidated")
				require.False(t, reader.Can(t.Context(), subject, "users:read"), "another service must bypass the stale grant")
				release.Do(func() { close(boundary.release) })
				require.NoError(t, <-result)
				require.False(t, reader.Can(t.Context(), subject, "users:read"))
			})
		}
	}
}

type (
	sharedCacheOutcomeDriver struct{ err error }
	sharedCacheOutcomeConn   struct{ commitResultConn }
)

func (d sharedCacheOutcomeDriver) Open(string) (driver.Conn, error) {
	return &sharedCacheOutcomeConn{commitResultConn: commitResultConn{err: d.err}}, nil
}

func (*sharedCacheOutcomeConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &cacheBoundaryRoleRows{value: false}, nil
}

func openSharedCacheDB(t *testing.T, commitErr error) *sql.DB {
	t.Helper()
	name := "goauth-shared-cache-outcome-" + uuid.NewString()
	sql.Register(name, sharedCacheOutcomeDriver{err: commitErr})
	db, err := sql.Open(name, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func TestSharedRBACCacheConcurrentConstructionCoalescesWrites(t *testing.T) {
	db := openSharedCacheDB(t, nil)
	cache := &concurrentInvalidationCache{}
	original, err := NewRBAC(db, cache)
	require.NoError(t, err)
	var workers sync.WaitGroup
	errors := make(chan error, 64)
	require.NoError(t, (&Store{db: db}).InAuthTransaction(t.Context(), func(ctx context.Context) error {
		for range 64 {
			workers.Go(func() {
				service, err := NewRBAC(db, cache)
				if err == nil {
					err = service.AssignRole(ctx, goauth.NewSubjectID(), "operator")
				}
				errors <- err
			})
		}
		workers.Wait()
		close(errors)
		for err := range errors {
			require.NoError(t, err)
		}
		return nil
	}))
	require.EqualValues(t, 1, cache.calls.Load(), "separate services share one managed guard and invalidation")
	require.True(t, original.Can(t.Context(), goauth.NewSubjectID(), "users:read"), "equal live caches keep acceleration")
}

func TestSharedRBACCachePreservesOutcomeAcrossServices(t *testing.T) {
	rejected := errors.New("host rollback")
	for _, tc := range []struct {
		name                                             string
		callbackErr, commitErr, invalidationErr, wantErr error
		allowed                                          bool
	}{
		{name: "rollback", callbackErr: rejected, wantErr: rejected, allowed: true},
		{name: sharedUnknownOutcome, commitErr: io.ErrUnexpectedEOF, wantErr: goauth.ErrOperationOutcomeUnknown},
		{name: sharedInvalidationFailure, invalidationErr: errors.New("cache unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openSharedCacheDB(t, tc.commitErr)
			cache := &concurrentInvalidationCache{err: tc.invalidationErr}
			writer, err := NewRBAC(db, cache)
			require.NoError(t, err)
			reader, err := NewRBAC(db, cache)
			require.NoError(t, err)
			authorizationCtx := t.Context()
			err = (&Store{db: db}).InAuthTransaction(t.Context(), func(ctx context.Context) error {
				if err := writer.AssignRole(ctx, goauth.NewSubjectID(), "operator"); err != nil {
					return err
				}
				require.False(t, reader.Can(authorizationCtx, goauth.NewSubjectID(), "users:read"))
				return tc.callbackErr
			})
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.allowed, reader.Can(t.Context(), goauth.NewSubjectID(), "users:read"))
		})
	}
}

type valueRBACCache struct {
	backend  *concurrentInvalidationCache
	identity any
}

func (c valueRBACCache) HasPermission(
	ctx context.Context, subject goauth.SubjectID, key rbac.PermissionKey,
) (allowed, found bool, err error) {
	return c.backend.HasPermission(ctx, subject, key)
}
func (c valueRBACCache) Invalidate(ctx context.Context) error { return c.backend.Invalidate(ctx) }

type cacheWithoutInvalidation struct{ rbac.Cache }

func TestSharedRBACCacheAmbiguousAssemblyBypassesAllServices(t *testing.T) {
	for _, mode := range []string{"nil writer", "different caches", sharedComparableValue, "noncomparable value"} {
		t.Run(mode, func(t *testing.T) {
			db := openSharedCacheDB(t, nil)
			var cache rbac.Cache = &concurrentInvalidationCache{}
			if mode == sharedComparableValue {
				cache = valueRBACCache{backend: &concurrentInvalidationCache{}, identity: "same"}
			}
			if mode == "noncomparable value" {
				cache = valueRBACCache{backend: &concurrentInvalidationCache{}, identity: []string{"same"}}
			}
			reader, err := NewRBAC(db, cache)
			require.NoError(t, err)
			subject := goauth.NewSubjectID()
			require.True(t, reader.Can(t.Context(), subject, "users:read"))
			secondCache := cache
			if mode == "nil writer" {
				secondCache = nil
			}
			if mode == "different caches" {
				secondCache = &concurrentInvalidationCache{}
			}
			writer, err := NewRBAC(db, secondCache)
			require.NoError(t, err)
			wantCached := mode == sharedComparableValue
			require.Equal(t, wantCached, reader.Can(t.Context(), subject, "users:read"))
			require.NoError(t, writer.AssignRole(t.Context(), subject, "operator"))
			again, err := NewRBAC(db, cache)
			require.NoError(t, err)
			require.Equal(t, wantCached, again.Can(t.Context(), subject, "users:read"), "matching a later delegate cannot clear fallback")
		})
	}
}

func TestSharedRBACCacheRejectedConstructorDoesNotDisableExistingCache(t *testing.T) {
	db := openSharedCacheDB(t, nil)
	cache := &concurrentInvalidationCache{}
	service, err := NewRBAC(db, cache)
	require.NoError(t, err)
	_, err = NewRBAC(db, cacheWithoutInvalidation{Cache: cache})
	require.ErrorContains(t, err, "requires invalidation support")
	require.True(t, service.Can(t.Context(), goauth.NewSubjectID(), "users:read"))
}

func abandonSharedRBACWrapper(
	t *testing.T, db *sql.DB, cache *concurrentInvalidationCache, wantErr error,
) weak.Pointer[transactionCache] {
	t.Helper()
	service, err := NewRBAC(db, cache)
	require.NoError(t, err)
	err = service.AssignRole(t.Context(), goauth.NewSubjectID(), "operator")
	if wantErr != nil {
		require.ErrorIs(t, err, wantErr)
	} else {
		require.NoError(t, err)
	}
	rbacCacheScopes.Lock()
	wrapper := rbacCacheScopes.entries[weak.Make(db)].cache
	rbacCacheScopes.Unlock()
	runtime.KeepAlive(service)
	return wrapper
}

func TestSharedRBACCacheCollectedWrapperCannotRestoreStaleCache(t *testing.T) {
	for _, mode := range []string{"healthy", sharedUnknownOutcome, sharedInvalidationFailure} {
		t.Run(mode, func(t *testing.T) {
			var commitErr, wantErr, invalidationErr error
			if mode == sharedUnknownOutcome {
				commitErr, wantErr = io.ErrUnexpectedEOF, goauth.ErrOperationOutcomeUnknown
			}
			if mode == sharedInvalidationFailure {
				invalidationErr = errors.New("cache unavailable")
			}
			db := openSharedCacheDB(t, commitErr)
			cache := &concurrentInvalidationCache{err: invalidationErr}
			old := abandonSharedRBACWrapper(t, db, cache, wantErr)
			require.Eventually(t, func() bool { runtime.GC(); return old.Value() == nil }, 5*time.Second, 10*time.Millisecond)
			service, err := NewRBAC(db, cache)
			require.NoError(t, err)
			require.False(t, service.Can(t.Context(), goauth.NewSubjectID(), "users:read"),
				"a retained delegate cannot resurrect dropped trust state")
			runtime.KeepAlive(cache)
		})
	}
}

func retiredSharedRBACScope(t *testing.T) weak.Pointer[sql.DB] {
	t.Helper()
	name := "goauth-retired-cache-scope-" + uuid.NewString()
	sql.Register(name, sharedCacheOutcomeDriver{})
	db, err := sql.Open(name, "")
	require.NoError(t, err)
	service, err := NewRBAC(db, &concurrentInvalidationCache{})
	require.NoError(t, err)
	require.NoError(t, db.Close())
	key := weak.Make(db)
	runtime.KeepAlive(service)
	return key
}

func TestSharedRBACCacheRegistryReleasesDatabase(t *testing.T) {
	key := retiredSharedRBACScope(t)
	require.Eventually(t, func() bool {
		runtime.GC()
		rbacCacheScopes.Lock()
		_, retained := rbacCacheScopes.entries[key]
		rbacCacheScopes.Unlock()
		return key.Value() == nil && !retained
	}, 5*time.Second, 10*time.Millisecond, "the registry must not keep the database or its delegate alive")
}
