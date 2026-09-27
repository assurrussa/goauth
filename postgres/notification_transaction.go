package postgres

import (
	"context"
	"database/sql"
	"fmt"
)

type notificationTxContextKey struct{}

// InNotificationTransaction joins all supported auth writes, notification
// enqueue, and security audit into one PostgreSQL transaction.
func (s *Store) InNotificationTransaction(ctx context.Context, fn func(context.Context) error) error {
	if existing := notificationTx(ctx); existing != nil {
		return fn(ctx)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin notification transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(context.WithValue(ctx, notificationTxContextKey{}, tx)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit notification transaction: %w", err)
	}
	return nil
}

func notificationTx(ctx context.Context) *sql.Tx {
	tx, _ := ctx.Value(notificationTxContextKey{}).(*sql.Tx)
	return tx
}

func (s *Store) beginWrite(ctx context.Context) (*sql.Tx, bool, error) {
	if tx := notificationTx(ctx); tx != nil {
		return tx, false, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
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

func (s *Store) notificationExecer(ctx context.Context) interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
} {
	if tx := notificationTx(ctx); tx != nil {
		return tx
	}
	return s.db
}
