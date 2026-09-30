package postgres

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

type transactionCache struct {
	db          *sql.DB
	delegate    rbac.Cache
	invalidator rbac.CacheInvalidator
	failed      atomic.Bool
}

func (c *transactionCache) HasPermission(
	ctx context.Context, subject goauth.SubjectID, key rbac.PermissionKey,
) (allowed, found bool, err error) {
	if c.failed.Load() {
		return false, true, nil
	}
	if _, managed := ctx.Value(notificationTxContextKey{}).(notificationTxScope); managed {
		return false, false, nil
	}
	return c.delegate.HasPermission(ctx, subject, key)
}

func (s *rbacStore) invalidateAfterCommit(ctx context.Context) {
	if s.cache == nil {
		return
	}
	callback := func() {
		// Commit is already durable; cancellation must not skip cache invalidation.
		if err := s.cache.invalidator.Invalidate(context.WithoutCancel(ctx)); err != nil {
			s.cache.failed.Store(true)
		}
	}
	scope, managed := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
	if managed && scope.db == s.db {
		scope.callbacks.add(callback, func() { s.cache.failed.Store(true) })
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
		s.cache.failed.Store(true)
	}
	return err
}
