package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

type transactionCache struct {
	db          *sql.DB
	delegate    rbac.Cache
	invalidator rbac.CacheInvalidator
	mu          sync.Mutex
	delegateMu  sync.RWMutex
	generation  uint64
	pending     int
	failed      bool
	uncertain   bool
}

func (c *transactionCache) HasPermission(
	ctx context.Context, subject goauth.SubjectID, key rbac.PermissionKey,
) (allowed, found bool, err error) {
	if _, managed := ctx.Value(notificationTxContextKey{}).(notificationTxScope); managed {
		return false, false, nil
	}
	c.mu.Lock()
	generation := c.generation
	bypass := c.failed || c.uncertain || c.pending > 0
	c.mu.Unlock()
	if bypass {
		return false, false, nil
	}
	// Never wait behind cache I/O: a pending invalidation uses authoritative
	// storage. Hold this lock through read-through fills before clearing cache.
	if !c.delegateMu.TryRLock() {
		return false, false, nil
	}
	defer c.delegateMu.RUnlock()
	c.mu.Lock()
	bypass = generation != c.generation || c.failed || c.uncertain || c.pending > 0
	c.mu.Unlock()
	if bypass {
		return false, false, nil
	}
	allowed, found, err = c.delegate.HasPermission(ctx, subject, key)
	c.mu.Lock()
	changed := generation != c.generation || c.failed || c.uncertain || c.pending > 0
	c.mu.Unlock()
	if changed {
		return false, false, nil
	}
	return allowed, found, err
}

func (c *transactionCache) invalidate(ctx context.Context) {
	// Publish bypass before external I/O. Readers never wait for invalidation,
	// even when a cache backend hangs; late cached reads are discarded.
	c.mu.Lock()
	c.generation++
	c.pending++
	c.mu.Unlock()
	// Serialize callbacks separately so their results cannot clear a newer
	// failure. The state lock is never held while calling the cache backend.
	c.delegateMu.Lock()
	defer c.delegateMu.Unlock()
	err := c.invalidator.Invalidate(ctx)
	c.mu.Lock()
	c.failed = err != nil
	c.pending--
	c.mu.Unlock()
}

func (c *transactionCache) markUncertain() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uncertain = true
	c.generation++
}

func (s *rbacStore) invalidateAfterCommit(ctx context.Context) {
	if s.cache == nil {
		return
	}
	callback := func() {
		// Commit is already durable; cancellation must not skip cache invalidation.
		s.cache.invalidate(context.WithoutCancel(ctx))
	}
	scope, managed := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
	if managed && scope.db == s.db {
		scope.callbacks.add(callback, s.cache.markUncertain)
		return
	}
	callback()
}

func (s *rbacStore) executor(ctx context.Context) SQLExecutor {
	executor, err := (&Store{db: s.db}).sqlExecutor(ctx)
	if err != nil {
		return rejectedSQLExecutor{db: s.db, err: err}
	}
	return executor
}

type rejectedSQLExecutor struct {
	db  *sql.DB
	err error
}

func (r rejectedSQLExecutor) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, r.err
}

func (r rejectedSQLExecutor) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, r.err
}

func (r rejectedSQLExecutor) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return rejectedQuerier{db: r.db}.QueryRowContext(ctx, query, args...)
}

func (s *rbacStore) finishWrite(tx *sql.Tx, owned bool) error {
	err := finishWrite(tx, owned)
	if s.cache != nil && errors.Is(err, goauth.ErrOperationOutcomeUnknown) {
		s.cache.markUncertain()
	}
	return err
}
