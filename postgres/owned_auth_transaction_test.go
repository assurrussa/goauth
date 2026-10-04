package postgres //nolint:testpackage // Verify managed scope ownership and exact SQL transaction outcomes.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type ownedTransactionTrace struct {
	begins, writes, commits, rollbacks atomic.Int64
	commitErr                          error
}
type (
	ownedTransactionDriver struct{ trace *ownedTransactionTrace }
	ownedTransactionConn   struct {
		notificationRecordingConn
		trace *ownedTransactionTrace
	}
	ownedTransactionTx struct{ trace *ownedTransactionTrace }
)

func (d ownedTransactionDriver) Open(string) (driver.Conn, error) {
	return &ownedTransactionConn{trace: d.trace}, nil
}

func (c *ownedTransactionConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.trace.begins.Add(1)
	return ownedTransactionTx{trace: c.trace}, nil
}

func (c *ownedTransactionConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.trace.writes.Add(1)
	return driver.RowsAffected(1), nil
}
func (tx ownedTransactionTx) Commit() error   { tx.trace.commits.Add(1); return tx.trace.commitErr }
func (tx ownedTransactionTx) Rollback() error { tx.trace.rollbacks.Add(1); return nil }

func ownedTransactionRuntime(t *testing.T, trace *ownedTransactionTrace) *Runtime {
	t.Helper()
	name := "goauth-owned-" + uuid.NewString()
	sql.Register(name, ownedTransactionDriver{trace: trace})
	db, err := sql.Open(name, "same-dsn")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return &Runtime{db: db, store: &Store{db: db}}
}

func TestOwnedAuthTransactionRejectsAmbientScope(t *testing.T) {
	t.Parallel()
	for _, ownedOuter := range []bool{false, true} {
		t.Run(map[bool]string{false: "joining outer", true: "owned outer"}[ownedOuter], func(t *testing.T) {
			t.Parallel()
			trace := &ownedTransactionTrace{}
			runtime := ownedTransactionRuntime(t, trace)
			alias := &Runtime{db: runtime.db, store: &Store{db: runtime.db}}
			outer := runtime.InAuthTransaction
			if ownedOuter {
				outer = runtime.InOwnedAuthTransaction
			}
			require.NoError(t, outer(t.Context(), func(ctx context.Context) error {
				for _, nested := range []*Runtime{runtime, alias} {
					called := false
					err := nested.InOwnedAuthTransaction(ctx, func(context.Context) error { called = true; return nil })
					require.ErrorIs(t, err, ErrAuthTransactionAlreadyActive)
					require.False(t, called)
				}
				require.EqualValues(t, 1, trace.begins.Load())
				require.Zero(t, trace.writes.Load())
				require.Zero(t, trace.commits.Load())
				return nil
			}))
			require.EqualValues(t, 1, trace.commits.Load())
		})
	}
}

func TestOwnedAuthTransactionRejectsForeignHandleWithSameDSN(t *testing.T) {
	t.Parallel()
	trace := &ownedTransactionTrace{}
	name := "goauth-owned-foreign-" + uuid.NewString()
	sql.Register(name, ownedTransactionDriver{trace: trace})
	runtimes := make([]*Runtime, 2)
	for i := range runtimes {
		db, err := sql.Open(name, "same-dsn")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, db.Close()) })
		runtimes[i] = &Runtime{db: db, store: &Store{db: db}}
	}
	require.NotSame(t, runtimes[0].db, runtimes[1].db)
	require.NoError(t, runtimes[0].InAuthTransaction(t.Context(), func(ctx context.Context) error {
		called := false
		err := runtimes[1].InOwnedAuthTransaction(ctx, func(context.Context) error { called = true; return nil })
		require.ErrorIs(t, err, errForeignNotificationTransaction)
		require.NotErrorIs(t, err, ErrAuthTransactionAlreadyActive)
		require.False(t, called)
		require.EqualValues(t, 1, trace.begins.Load())
		require.Zero(t, trace.writes.Load())
		return nil
	}))
}

func TestOwnedAuthTransactionOutcomeAndResponseBoundary(t *testing.T) {
	t.Parallel()
	rejection := errors.New("host rejected")
	for _, tc := range []struct {
		name                   string
		callbackErr, commitErr error
		outcome                authTransactionOutcome
		unknown                bool
	}{
		{name: "confirmed commit", outcome: authTransactionCommitted},
		{name: "callback rollback", callbackErr: rejection},
		{name: "known rejected commit", commitErr: &pgconn.PgError{Code: "40001"}},
		{name: "known finished transaction", commitErr: sql.ErrTxDone},
		{name: "unconfirmed commit response", commitErr: io.ErrUnexpectedEOF, outcome: authTransactionUnknown, unknown: true},
		{name: "commit cancellation", commitErr: context.Canceled, outcome: authTransactionUnknown, unknown: true},
		{name: "commit deadline", commitErr: context.DeadlineExceeded, outcome: authTransactionUnknown, unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			trace := &ownedTransactionTrace{commitErr: tc.commitErr}
			runtime := ownedTransactionRuntime(t, trace)
			var outcomes []authTransactionOutcome
			response, err := prepareOwnedTransactionResponse(t.Context(), runtime, func(ctx context.Context) error {
				scope, ok := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
				require.True(t, ok)
				scope.callbacks.entries = append(scope.callbacks.entries, authTransactionCallback{
					afterCommit:   func() { outcomes = append(outcomes, authTransactionCommitted) },
					afterRollback: func() { outcomes = append(outcomes, authTransactionRolledBack) },
					afterUnknown:  func() { outcomes = append(outcomes, authTransactionUnknown) },
				})
				// Legacy nested API and low-level stores join the owned transaction.
				require.NoError(t, runtime.InAuthTransaction(ctx, func(nested context.Context) error {
					tx, owned, err := runtime.store.beginWrite(nested)
					require.NoError(t, err)
					require.False(t, owned)
					require.Same(t, scope.tx, tx)
					executor, err := runtime.SQLExecutor(nested)
					require.NoError(t, err)
					_, err = executor.ExecContext(nested, "owned-write")
					require.NoError(t, err)
					return finishWrite(tx, owned)
				}))
				require.EqualValues(t, 1, trace.begins.Load())
				require.Zero(t, trace.commits.Load())
				require.Empty(t, outcomes)
				return tc.callbackErr
			})
			require.Equal(t, []authTransactionOutcome{tc.outcome}, outcomes)
			require.Equal(t, tc.unknown, errors.Is(err, goauth.ErrOperationOutcomeUnknown))
			switch {
			case tc.callbackErr != nil:
				require.ErrorIs(t, err, tc.callbackErr)
				require.EqualValues(t, 1, trace.rollbacks.Load())
				require.Zero(t, trace.commits.Load())
			case tc.commitErr != nil:
				require.ErrorIs(t, err, tc.commitErr)
				require.EqualValues(t, 1, trace.commits.Load())
			default:
				require.NoError(t, err)
				require.Equal(t, "provisional-secret", response)
				require.EqualValues(t, 1, trace.commits.Load())
			}
			if err != nil {
				require.Empty(t, response, "never publish a provisional response on failure")
			}
			require.EqualValues(t, 1, trace.writes.Load())
		})
	}
}

func prepareOwnedTransactionResponse(ctx context.Context, runtime *Runtime, fn func(context.Context) error) (string, error) {
	var prepared string
	err := runtime.InOwnedAuthTransaction(ctx, func(txctx context.Context) error {
		prepared = "provisional-secret"
		return fn(txctx)
	})
	if err != nil {
		return "", err
	}
	return prepared, nil
}

func TestOwnedAuthTransactionCancellationAndUninitialized(t *testing.T) {
	t.Parallel()
	for _, runtime := range []*Runtime{nil, {}} {
		called := false
		err := runtime.InOwnedAuthTransaction(t.Context(), func(context.Context) error { called = true; return nil })
		require.Error(t, err)
		require.False(t, called)
	}
	trace := &ownedTransactionTrace{}
	runtime := ownedTransactionRuntime(t, trace)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	response, err := prepareOwnedTransactionResponse(ctx, runtime, func(context.Context) error {
		t.Error("cancelled begin called callback")
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, response)
	require.Zero(t, trace.begins.Load())
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	response, err = prepareOwnedTransactionResponse(ctx, runtime, func(context.Context) error {
		cancel()
		return ctx.Err()
	})
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Empty(t, response)
	require.EqualValues(t, 1, trace.begins.Load())
	require.Zero(t, trace.commits.Load())
}
