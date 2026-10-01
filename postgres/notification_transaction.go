package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/assurrussa/goauth"
)

type (
	notificationTxContextKey struct{}
	notificationTxScope      struct {
		db        *sql.DB
		tx        *sql.Tx
		callbacks *authTransactionCallbacks
	}
)

// All operations sharing the transaction context share this callback owner.
// Keep outcome hooks together and execute them outside the registration lock.
type authTransactionCallbacks struct {
	mu      sync.Mutex
	entries []authTransactionCallback
}

type authTransactionCallback struct {
	afterCommit   func()
	afterUnknown  func()
	afterRollback func()
}

type authTransactionOutcome uint8

const (
	authTransactionRolledBack authTransactionOutcome = iota
	authTransactionCommitted
	authTransactionUnknown
)

func (c *authTransactionCallbacks) add(afterCommit, afterUnknown, afterRollback func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, authTransactionCallback{
		afterCommit: afterCommit, afterUnknown: afterUnknown, afterRollback: afterRollback,
	})
}

func (c *authTransactionCallbacks) run(outcome authTransactionOutcome) {
	c.mu.Lock()
	entries := c.entries
	c.entries = nil
	c.mu.Unlock()
	for _, entry := range entries {
		callback := entry.afterRollback
		switch outcome {
		case authTransactionCommitted:
			callback = entry.afterCommit
		case authTransactionUnknown:
			callback = entry.afterUnknown
		case authTransactionRolledBack:
		}
		if callback != nil {
			callback()
		}
	}
}

var errForeignNotificationTransaction = errors.New("notification transaction belongs to a different database handle")

// InNotificationTransaction joins the participating managed auth writes,
// notification enqueue, and security audit on this database handle.
func (s *Store) InNotificationTransaction(ctx context.Context, fn func(context.Context) error) error {
	return s.InAuthTransaction(ctx, fn)
}

// InAuthTransaction atomically commits participating auth, audit and event writes.
func (s *Store) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	existing, err := s.notificationTx(ctx)
	if err != nil {
		return err
	}
	if existing != nil {
		return fn(ctx)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin notification transaction: %w", err)
	}
	scope := notificationTxScope{db: s.db, tx: tx, callbacks: &authTransactionCallbacks{}}
	defer func() {
		_ = tx.Rollback()
		scope.callbacks.run(authTransactionRolledBack)
	}()
	if err := fn(context.WithValue(ctx, notificationTxContextKey{}, scope)); err != nil {
		return err
	}
	if err := commitAuthTransaction(tx); err != nil {
		if errors.Is(err, goauth.ErrOperationOutcomeUnknown) {
			scope.callbacks.run(authTransactionUnknown)
		}
		return fmt.Errorf("commit auth transaction: %w", err)
	}
	scope.callbacks.run(authTransactionCommitted)
	return nil
}

func (s *Store) notificationTx(ctx context.Context) (*sql.Tx, error) {
	scope, ok := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
	if !ok {
		//nolint:nilnil // A nil transaction means this context has no managed scope.
		return nil, nil
	}
	if scope.db != s.db {
		return nil, errForeignNotificationTransaction
	}
	return scope.tx, nil
}

func (s *Store) beginWrite(ctx context.Context) (*sql.Tx, bool, error) {
	tx, err := s.notificationTx(ctx)
	if err != nil {
		return nil, false, err
	}
	if tx != nil {
		return tx, false, nil
	}
	tx, err = s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	return tx, true, err
}

func finishWrite(tx *sql.Tx, owned bool) error {
	if !owned {
		return nil
	}
	return commitAuthTransaction(tx)
}

func rollbackWrite(tx *sql.Tx, owned bool) {
	if owned {
		_ = tx.Rollback()
	}
}

type notificationExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type rejectedNotificationExec struct{ err error }

func (r rejectedNotificationExec) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, r.err
}

func (s *Store) notificationExecer(ctx context.Context) notificationExec {
	tx, err := s.notificationTx(ctx)
	if err != nil {
		return rejectedNotificationExec{err: err}
	}
	if tx != nil {
		return tx
	}
	return s.db
}

// queryer routes reads through the same transaction as writes.
func (s *Store) queryer(ctx context.Context) queryRower {
	tx, err := s.notificationTx(ctx)
	if err != nil {
		return rejectedQuerier{db: s.db}
	}
	if tx != nil {
		return tx
	}
	return s.db
}

type rejectedQuerier struct{ db *sql.DB }

func (r rejectedQuerier) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	// database/sql has no public error-row constructor. A cancelled query creates
	// an error row without reaching the server; writes reject the foreign scope.
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	return r.db.QueryRowContext(ctx, query, args...)
}

func commitAuthTransaction(tx *sql.Tx) error {
	err := tx.Commit()
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) || errors.Is(err, sql.ErrTxDone) {
		return err
	}
	return errors.Join(goauth.ErrOperationOutcomeUnknown, err)
}
