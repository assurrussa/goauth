package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type (
	notificationTxContextKey struct{}
	notificationTxScope      struct {
		db *sql.DB
		tx *sql.Tx
	}
)

var errForeignNotificationTransaction = errors.New("notification transaction belongs to a different database handle")

// InNotificationTransaction joins the participating managed auth writes,
// notification enqueue, and security audit on this database handle.
func (s *Store) InNotificationTransaction(ctx context.Context, fn func(context.Context) error) error {
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
	defer func() { _ = tx.Rollback() }()
	if err := fn(context.WithValue(ctx, notificationTxContextKey{}, notificationTxScope{db: s.db, tx: tx})); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit notification transaction: %w", err)
	}
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
	return tx.Commit()
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
