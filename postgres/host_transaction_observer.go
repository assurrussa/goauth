package postgres

import (
	"context"
	"errors"
)

// AuthTransactionOutcome is the outer managed transaction's final outcome.
type AuthTransactionOutcome uint8

const (
	// AuthTransactionRolledBack confirms no writes were committed.
	AuthTransactionRolledBack AuthTransactionOutcome = iota
	// AuthTransactionCommitted confirms commit.
	AuthTransactionCommitted
	// AuthTransactionUnknown means commit may have succeeded. Fence dependent
	// caches and reconcile; do not assume rollback or blindly retry writes.
	AuthTransactionUnknown
)

// AuthTransactionObserver identifies a host's transaction completion observer.
// Keep one pointer per cache/consumer to coalesce registrations in nested scopes.
// Do not mutate it after registration. Notify runs synchronously after transaction
// completion, outside registration locks; it must be bounded and must not panic.
// It must not reuse a transaction context/executor. For cache invalidation use a
// separately bounded context independent of request cancellation. Notify cannot
// change the already final database outcome and is not a durable event delivery.
type AuthTransactionObserver struct {
	Notify func(AuthTransactionOutcome)
}

// ObserveAuthTransaction registers observer once per outer transaction and pointer.
// It rejects missing, foreign or completed scopes, and never invokes Notify early.
// Register before the corresponding mutation and propagate registration errors.
// Rollback, including panic unwinding, invokes the rollback outcome; an uncertain
// commit invokes Unknown. Low-level operations without managed scopes are not
// observed: hosts must wrap their writes in InAuthTransaction.
func (r *Runtime) ObserveAuthTransaction(ctx context.Context, observer *AuthTransactionObserver) error {
	if r == nil || r.store == nil {
		return errors.New("PostgreSQL Runtime is not initialized")
	}
	if observer == nil || observer.Notify == nil {
		return errors.New("auth transaction observer is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	scope, ok := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
	if !ok {
		return errors.New("managed auth transaction is required")
	}
	if scope.db != r.db {
		return errForeignNotificationTransaction
	}
	c := scope.callbacks
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.completed {
		return errors.New("auth transaction is already completed")
	}
	if _, ok := c.observers[observer]; ok {
		return nil
	}
	if c.observers == nil {
		c.observers = make(map[*AuthTransactionObserver]struct{})
	}
	c.observers[observer] = struct{}{}
	notify := observer.Notify
	c.entries = append(c.entries, authTransactionCallback{
		afterCommit:   func() { notify(AuthTransactionCommitted) },
		afterRollback: func() { notify(AuthTransactionRolledBack) },
		afterUnknown:  func() { notify(AuthTransactionUnknown) },
	})
	return nil
}
