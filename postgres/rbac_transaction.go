package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

const cacheInvalidationTimeout = 2 * time.Second

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

// beginInvalidation publishes bypass before a write can become visible. Each
// reservation must be completed by invalidation or released after rollback.
func (c *transactionCache) beginInvalidation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	c.pending++
	return c.generation
}

func (c *transactionCache) cancelInvalidation() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending--
}

func (c *transactionCache) invalidatePending(ctx context.Context, generation uint64) {
	// Serialize callbacks separately so their results cannot clear a newer
	// failure. The state lock is never held while calling the cache backend.
	if err := c.lockInvalidation(ctx); err != nil {
		c.finishInvalidation(generation, err)
		return
	}
	defer c.delegateMu.Unlock()

	err := c.invalidator.Invalidate(ctx)
	if err == nil {
		err = ctx.Err()
	}
	c.finishInvalidation(generation, err)
}

func (c *transactionCache) lockInvalidation(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.delegateMu.TryLock() {
		return nil
	}
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := ctx.Err(); err != nil {
				return err
			}
			if c.delegateMu.TryLock() {
				return nil
			}
		}
	}
}

func (c *transactionCache) finishInvalidation(generation uint64, err error) {
	c.mu.Lock()
	// An older success cannot clear a newer timeout while it waited for the
	// delegate lock. A later completed invalidation can safely restore reads.
	if err != nil {
		c.failed = true
	} else if generation == c.generation {
		c.failed = false
	}
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
	generation := s.cache.beginInvalidation()
	callback := func() { s.invalidatePendingAfterCommit(ctx, generation) }
	scope, managed := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
	if managed && scope.db == s.db {
		scope.callbacks.add(callback, func() {
			s.cache.markUncertain()
			s.cache.cancelInvalidation()
		}, s.cache.cancelInvalidation)
		return
	}
	callback()
}

func (s *rbacStore) invalidatePendingAfterCommit(ctx context.Context, generation uint64) {
	// Commit is already durable; cancellation must not skip cache invalidation.
	invalidationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cacheInvalidationTimeout)
	defer cancel()
	s.cache.invalidatePending(invalidationCtx, generation)
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

func (s *rbacStore) finishWrite(ctx context.Context, tx *sql.Tx, owned bool) error {
	if !owned {
		s.invalidateAfterCommit(ctx)
		return nil
	}
	if s.cache == nil {
		return finishWrite(tx, true)
	}
	// Standalone transactions need the same pre-commit guard as managed writes.
	generation := s.cache.beginInvalidation()
	if err := finishWrite(tx, true); err != nil {
		if errors.Is(err, goauth.ErrOperationOutcomeUnknown) {
			s.cache.markUncertain()
		}
		s.cache.cancelInvalidation()
		return err
	}
	s.invalidatePendingAfterCommit(ctx, generation)
	return nil
}
