package postgres //nolint:testpackage // Verify private cache bypass and recovery boundaries.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

type recoveryCache struct {
	err   error
	reads int
}

func (c *recoveryCache) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (allowed, found bool, err error) {
	c.reads++
	return true, true, nil
}

func (c *recoveryCache) Invalidate(context.Context) error { return c.err }

func TestCacheFailureBypassesAndRecovers(t *testing.T) {
	delegate := &recoveryCache{}
	cache := &transactionCache{delegate: delegate, invalidator: delegate}
	subject := goauth.NewSubjectID()
	assertRead := func(wantFound bool) {
		t.Helper()
		allowed, found, err := cache.HasPermission(t.Context(), subject, "users:read")
		require.NoError(t, err)
		require.Equal(t, wantFound, found)
		require.Equal(t, wantFound, allowed)
	}
	assertRead(true)
	delegate.err = errors.New("cache unavailable")
	cache.invalidate(t.Context())
	assertRead(false)
	require.Equal(t, 1, delegate.reads, "suspect cache must never be read")
	delegate.err = nil
	cache.invalidate(t.Context())
	assertRead(true)
	cache.markUncertain()
	cache.invalidate(t.Context())
	assertRead(false)
	require.Equal(t, 2, delegate.reads, "invalidation cannot prove an uncertain transaction has settled")
}

type authoritativePermissionStore struct {
	allowed bool
	err     error
	calls   int
}

func (s *authoritativePermissionStore) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, error) {
	s.calls++
	return s.allowed, s.err
}

func TestSuspectCacheUsesAuthoritativePermissions(t *testing.T) {
	delegate := &recoveryCache{err: errors.New("cache unavailable")}
	cache := &transactionCache{delegate: delegate, invalidator: delegate}
	cache.invalidate(t.Context())
	store := &authoritativePermissionStore{allowed: true}
	service, err := rbac.New(store, cache)
	require.NoError(t, err)
	subject := goauth.NewSubjectID()
	require.True(t, service.Can(t.Context(), subject, "users:read"))
	store.allowed = false
	require.False(t, service.Can(t.Context(), subject, "users:read"))
	store.allowed = true
	store.err = errors.New("database unavailable")
	require.False(t, service.Can(t.Context(), subject, "users:read"))
	require.Equal(t, 3, store.calls)
	require.Zero(t, delegate.reads)
}

type blockedInvalidationCache struct {
	recoveryCache
	entered, release chan struct{}
}

func (c *blockedInvalidationCache) Invalidate(context.Context) error {
	close(c.entered)
	<-c.release
	return nil
}

func TestCacheReadsBypassBlockedInvalidation(t *testing.T) {
	delegate := &blockedInvalidationCache{entered: make(chan struct{}), release: make(chan struct{})}
	cache := &transactionCache{delegate: delegate, invalidator: delegate, failed: true}
	done := make(chan struct{})
	go func() { cache.invalidate(t.Context()); close(done) }()
	t.Cleanup(func() { close(delegate.release); <-done })
	<-delegate.entered
	store := &authoritativePermissionStore{allowed: true}
	service, err := rbac.New(store, cache)
	require.NoError(t, err)
	result := make(chan bool, 1)
	go func() { result <- service.Can(t.Context(), goauth.NewSubjectID(), "users:read") }()
	select {
	case allowed := <-result:
		require.True(t, allowed, "a blocked invalidation must not block authoritative authorization")
	case <-time.After(time.Second):
		t.Fatal("authorization waited for a blocked cache invalidation")
	}
	require.Zero(t, delegate.reads)
}

type blockedReadCache struct {
	entered, release chan struct{}
	cached           bool
	first            bool
}

func (c *blockedReadCache) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (allowed, found bool, err error) {
	if !c.first {
		c.first = true
		close(c.entered)
		<-c.release
		c.cached = true // A read-through fill using a pre-revocation snapshot.
	}
	return c.cached, c.cached, nil
}

func (c *blockedReadCache) Invalidate(context.Context) error { c.cached = false; return nil }

func TestLateCachedGrantIsDiscardedAfterInvalidation(t *testing.T) {
	delegate := &blockedReadCache{entered: make(chan struct{}), release: make(chan struct{})}
	cache := &transactionCache{delegate: delegate, invalidator: delegate}
	store := &authoritativePermissionStore{}
	service, err := rbac.New(store, cache)
	require.NoError(t, err)
	subject := goauth.NewSubjectID()
	result := make(chan bool, 1)
	go func() { result <- service.Can(t.Context(), subject, "users:read") }()
	<-delegate.entered
	done := make(chan struct{})
	go func() { cache.invalidate(t.Context()); close(done) }()
	require.Eventually(t, func() bool {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		return cache.pending > 0
	}, time.Second, time.Millisecond)
	close(delegate.release)
	require.False(t, <-result, "a cached grant from before invalidation cannot escape revocation")
	<-done
	require.False(t, service.Can(t.Context(), subject, "users:read"), "late read-through fills must be invalidated too")
	require.Equal(t, 2, store.calls)
}
