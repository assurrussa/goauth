package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

func TestCheckDistinguishesDenialFromDependencyFailure(t *testing.T) {
	t.Parallel()
	dependencyErr := errors.New("authorization dependency unavailable")
	wrappedErr := fmt.Errorf("dependency operation: %w", dependencyErr)
	cases := []struct {
		name           string
		storeAllowed   bool
		storeErr       error
		cache          rbac.Cache
		wantAllowed    bool
		wantErr        error
		wantStoreCalls int
	}{
		{name: "store allow", storeAllowed: true, wantAllowed: true, wantStoreCalls: 1},
		{name: "store deny", wantStoreCalls: 1},
		{name: "cache allow", cache: cacheStub{allowed: true, found: true}, wantAllowed: true},
		{name: "cache deny", storeAllowed: true, cache: cacheStub{found: true}},
		{
			name: "cache miss allow", storeAllowed: true, cache: cacheStub{},
			wantAllowed: true, wantStoreCalls: 1,
		},
		{name: "cache miss deny", cache: cacheStub{}, wantStoreCalls: 1},
		{
			name: "cache failure", storeAllowed: true,
			cache: cacheStub{allowed: true, found: true, err: wrappedErr}, wantErr: dependencyErr,
		},
		{
			name: "cache miss failure", storeAllowed: true,
			cache: cacheStub{err: wrappedErr}, wantErr: dependencyErr,
		},
		{
			name: "store failure", storeAllowed: true, storeErr: wrappedErr,
			wantErr: dependencyErr, wantStoreCalls: 1,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			storeCalls := 0
			store := permissionStoreFunc(func(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, error) {
				storeCalls++
				return test.storeAllowed, test.storeErr
			})
			service, err := rbac.New(store, test.cache)
			require.NoError(t, err)
			subjectID := goauth.NewSubjectID()
			key := rbac.MustPermissionKey("content", "read")

			allowed, err := service.Check(t.Context(), subjectID, key)
			require.Equal(t, test.wantAllowed, allowed)
			require.Equal(t, test.wantStoreCalls, storeCalls)
			if test.wantErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.wantErr)
			}
			require.Equal(t, test.wantAllowed, service.Can(t.Context(), subjectID, key))
			if test.wantAllowed {
				require.NoError(t, service.Require(t.Context(), subjectID, key))
			} else {
				require.ErrorIs(t, service.Require(t.Context(), subjectID, key), rbac.ErrPermissionDenied)
			}
		})
	}
}

func TestCheckValidatesBeforeDependencies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		subjectID goauth.SubjectID
		key       rbac.PermissionKey
		wantErr   error
	}{
		{name: "zero subject", key: "content:read", wantErr: goauth.ErrInvalidSubjectID},
		{name: "subject before key", key: "invalid", wantErr: goauth.ErrInvalidSubjectID},
		{name: "invalid key", subjectID: goauth.NewSubjectID(), key: "invalid", wantErr: rbac.ErrInvalidPermissionKey},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := permissionStoreFunc(func(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, error) {
				t.Fatal("invalid input reached the store")
				return false, nil
			})
			cache := permissionCacheFunc(func(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, bool, error) {
				t.Fatal("invalid input reached the cache")
				return false, false, nil
			})
			service, err := rbac.New(store, cache)
			require.NoError(t, err)

			allowed, err := service.Check(t.Context(), test.subjectID, test.key)
			require.False(t, allowed)
			require.ErrorIs(t, err, test.wantErr)
			require.False(t, service.Can(t.Context(), test.subjectID, test.key))
			require.ErrorIs(t, service.Require(t.Context(), test.subjectID, test.key), rbac.ErrPermissionDenied)
		})
	}
}

func TestCheckPreservesDependencyContextErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		cache    bool
		deadline bool
		wantErr  error
	}{
		{name: "store canceled", wantErr: context.Canceled},
		{name: "cache canceled", cache: true, wantErr: context.Canceled},
		{name: "store deadline", deadline: true, wantErr: context.DeadlineExceeded},
		{name: "cache deadline", cache: true, deadline: true, wantErr: context.DeadlineExceeded},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if test.deadline {
				ctx, cancel = context.WithDeadline(t.Context(), time.Time{})
				defer cancel()
			}
			require.ErrorIs(t, ctx.Err(), test.wantErr)
			store := permissionStoreFunc(func(ctx context.Context, _ goauth.SubjectID, _ rbac.PermissionKey) (bool, error) {
				return true, ctx.Err()
			})
			var cache rbac.Cache
			if test.cache {
				cache = permissionCacheFunc(func(ctx context.Context, _ goauth.SubjectID, _ rbac.PermissionKey) (bool, bool, error) {
					return true, true, ctx.Err()
				})
			}
			service, err := rbac.New(store, cache)
			require.NoError(t, err)
			subjectID := goauth.NewSubjectID()
			key := rbac.MustPermissionKey("content", "read")

			allowed, err := service.Check(ctx, subjectID, key)
			require.False(t, allowed)
			require.ErrorIs(t, err, test.wantErr)
			require.False(t, service.Can(ctx, subjectID, key))
			require.ErrorIs(t, service.Require(ctx, subjectID, key), rbac.ErrPermissionDenied)
		})
	}
}

func TestCheckPreservesSuccessfulDependencyResultAfterCancellation(t *testing.T) {
	t.Parallel()
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%t", cached), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			var cache rbac.Cache
			if cached {
				cache = cacheStub{allowed: true, found: true}
			}
			service, err := rbac.New(&storeStub{allowed: true}, cache)
			require.NoError(t, err)
			subjectID := goauth.NewSubjectID()
			key := rbac.MustPermissionKey("content", "read")

			allowed, err := service.Check(ctx, subjectID, key)
			require.NoError(t, err)
			require.True(t, allowed)
			require.True(t, service.Can(ctx, subjectID, key))
			require.NoError(t, service.Require(ctx, subjectID, key))
		})
	}
}

type permissionStoreFunc func(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, error)

func (f permissionStoreFunc) HasPermission(
	ctx context.Context,
	subjectID goauth.SubjectID,
	key rbac.PermissionKey,
) (bool, error) {
	return f(ctx, subjectID, key)
}

type permissionCacheFunc func(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, bool, error)

func (f permissionCacheFunc) HasPermission(
	ctx context.Context,
	subjectID goauth.SubjectID,
	key rbac.PermissionKey,
) (bool, bool, error) {
	return f(ctx, subjectID, key)
}
