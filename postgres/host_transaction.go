package postgres

import (
	"context"
	"database/sql"
	"errors"
)

// SQLExecutor provides transaction-aware SQL without transaction ownership.
type SQLExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// sqlExecutor deliberately prevents type assertion to *sql.Tx and its commit methods.
type sqlExecutor struct{ SQLExecutor }

// SQLExecutor returns an executor on the Runtime database, joining the managed
// transaction in ctx. A context owned by another database is rejected.
func (r *Runtime) SQLExecutor(ctx context.Context) (SQLExecutor, error) {
	if r == nil || r.store == nil {
		return nil, errors.New("PostgreSQL Runtime is not initialized")
	}
	return r.store.sqlExecutor(ctx)
}

func (s *Store) sqlExecutor(ctx context.Context) (SQLExecutor, error) {
	tx, err := s.notificationTx(ctx)
	if err != nil {
		return nil, err
	}
	if tx != nil {
		return sqlExecutor{tx}, nil
	}
	return sqlExecutor{s.db}, nil
}

// InAuthTransaction shares canonical auth, audit, RBAC and host SQL writes on
// this exact database handle. Nested operations join; only the outer call commits.
// fn must wait for all concurrent operations using its context before returning.
// The transaction context and its SQL executors must not outlive fn.
// Consume and close SQL result sets before another operation uses the same
// transaction connection; mixed Query/Exec calls must be serialized.
func (r *Runtime) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if r == nil || r.store == nil {
		return errors.New("PostgreSQL Runtime is not initialized")
	}
	return r.store.InAuthTransaction(ctx, fn)
}

// Database returns the canonical database handle shared by managed transactions.
// Hosts must obtain context-scoped SQLExecutor for writes within those transactions.
func (r *Runtime) Database() *sql.DB {
	if r == nil {
		return nil
	}
	return r.db
}
