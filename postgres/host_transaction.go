package postgres

import (
	"context"
	"database/sql"
	"errors"
)

// ErrAuthTransactionAlreadyActive means an owned auth transaction was requested
// from a context already carrying a managed transaction on the same database handle.
// The owned callback is not invoked and no new transaction is started.
var ErrAuthTransactionAlreadyActive = errors.New("auth transaction is already active")

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

// InOwnedAuthTransaction owns the outermost managed auth transaction on this exact
// database handle. It rejects an ambient same-handle scope with
// ErrAuthTransactionAlreadyActive before invoking fn or starting a transaction;
// a scope belonging to another database handle is also rejected. InAuthTransaction
// and participating low-level operations may still join inside fn.
//
// A nil return confirms commit. Prepared secrets, tokens and authorization results
// remain provisional until then: fn must not publish them, and callers must withhold
// them on every error, including goauth.ErrOperationOutcomeUnknown. An unknown
// outcome must not be treated as a rollback or blindly retried.
// The context, executor, concurrency and result-set rules of InAuthTransaction apply.
func (r *Runtime) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if r == nil || r.store == nil {
		return errors.New("PostgreSQL Runtime is not initialized")
	}
	return r.store.inAuthTransaction(ctx, fn, true)
}

// Database returns the canonical database handle shared by managed transactions.
// Hosts must obtain context-scoped SQLExecutor for writes within those transactions.
func (r *Runtime) Database() *sql.DB {
	if r == nil {
		return nil
	}
	return r.db
}
