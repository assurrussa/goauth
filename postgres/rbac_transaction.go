package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

const (
	cacheInvalidationTimeout     = 2 * time.Second
	rbacOperationRecoveryTimeout = 2 * time.Second
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

// reserveManagedInvalidation coalesces writes by transaction/cache identity.
// Register the guard before SQL mutation, including operations that later fail.
func (s *rbacStore) reserveManagedInvalidation(ctx context.Context, callbacks *authTransactionCallbacks) {
	if s.cache == nil {
		return
	}
	callbacks.mu.Lock()
	defer callbacks.mu.Unlock()
	if _, reserved := callbacks.caches[s.cache]; reserved {
		return
	}
	if callbacks.caches == nil {
		callbacks.caches = make(map[*transactionCache]struct{})
	}
	generation := s.cache.beginInvalidation()
	callbacks.caches[s.cache] = struct{}{}
	callbacks.entries = append(callbacks.entries, authTransactionCallback{
		afterCommit: func() { s.invalidatePendingAfterCommit(ctx, generation) },
		afterUnknown: func() {
			s.cache.markUncertain()
			s.cache.cancelInvalidation()
		},
		afterRollback: s.cache.cancelInvalidation,
	})
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

// rbacWrite protects each operation, even if its error is handled by the host.
// Managed RBAC operations serialize their savepoints on the shared connection.
type rbacWrite struct {
	store      *rbacStore
	tx         *sql.Tx
	owned      bool
	generation uint64
	unlock     func()
	finished   bool
}

func (s *rbacStore) beginWrite(ctx context.Context) (*rbacWrite, error) {
	w := &rbacWrite{store: s}
	scope, managed := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
	if managed && scope.db == s.db {
		scope.callbacks.rbacMu.Lock()
		w.unlock = scope.callbacks.rbacMu.Unlock
	}
	if err := ctx.Err(); err != nil {
		if w.unlock != nil {
			w.unlock()
		}
		return nil, err
	}
	var err error
	w.tx, w.owned, err = (&Store{db: s.db}).beginWrite(ctx)
	if err != nil {
		if w.unlock != nil {
			w.unlock()
		}
		return nil, err
	}
	if w.owned {
		if s.cache != nil {
			w.generation = s.cache.beginInvalidation()
		}
	} else {
		s.reserveManagedInvalidation(ctx, scope.callbacks)
		if _, err := w.tx.ExecContext(ctx, `SAVEPOINT goauth_rbac_operation`); err != nil {
			// A failed savepoint cannot support safe operation-level recovery.
			_ = w.tx.Rollback()
			w.unlock()
			return nil, fmt.Errorf("begin RBAC operation savepoint: %w", err)
		}
	}
	return w, nil
}

func (w *rbacWrite) finish(ctx context.Context) error {
	if !w.owned {
		if _, err := w.tx.ExecContext(ctx, `RELEASE SAVEPOINT goauth_rbac_operation`); err != nil {
			return fmt.Errorf("release RBAC operation savepoint: %w", err)
		}
		w.finished = true
		return nil
	}
	// Keep the guard through the commit result and the detached invalidation.
	w.finished = true
	if err := finishWrite(w.tx, true); err != nil {
		if w.store.cache != nil {
			if errors.Is(err, goauth.ErrOperationOutcomeUnknown) {
				w.store.cache.markUncertain()
			}
			w.store.cache.cancelInvalidation()
		}
		return err
	}
	if w.store.cache != nil {
		w.store.invalidatePendingAfterCommit(ctx, w.generation)
	}
	return nil
}

func (w *rbacWrite) rollback(ctx context.Context) {
	if w.unlock != nil {
		defer w.unlock()
	}
	if w.owned {
		_ = w.tx.Rollback()
		if !w.finished && w.store.cache != nil {
			w.store.cache.cancelInvalidation()
		}
		return
	}
	if w.finished {
		return
	}
	// A child operation cancellation must not prevent restoring the savepoint.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rbacOperationRecoveryTimeout)
	defer cancel()
	if _, err := w.tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT goauth_rbac_operation`); err != nil {
		_ = w.tx.Rollback() // Fail closed: the host cannot commit partial writes.
		return
	}
	if _, err := w.tx.ExecContext(ctx, `RELEASE SAVEPOINT goauth_rbac_operation`); err != nil {
		_ = w.tx.Rollback()
	}
}
