package postgres //nolint:testpackage // Verify exact managed scope ownership without database queries.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthTransactionActive(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "owned"}[owned], func(t *testing.T) {
			trace := &ownedTransactionTrace{}
			r := ownedTransactionRuntime(t, trace)
			alias := &Runtime{db: r.db, store: &Store{db: r.db}}
			foreign := ownedTransactionRuntime(t, &ownedTransactionTrace{})
			active, err := r.AuthTransactionActive(t.Context())
			require.NoError(t, err)
			require.False(t, active)
			var retained context.Context
			run := r.InAuthTransaction
			if owned {
				run = r.InOwnedAuthTransaction
			}
			require.NoError(t, run(t.Context(), func(ctx context.Context) error {
				retained = ctx
				active, err = alias.AuthTransactionActive(ctx)
				require.NoError(t, err)
				require.True(t, active)
				active, err = foreign.AuthTransactionActive(ctx)
				require.ErrorIs(t, err, errForeignNotificationTransaction)
				require.False(t, active)
				return r.InAuthTransaction(ctx, func(nested context.Context) error {
					active, err = r.AuthTransactionActive(nested)
					require.NoError(t, err)
					require.True(t, active)
					canceled, cancel := context.WithCancel(nested)
					cancel()
					active, err = r.AuthTransactionActive(canceled)
					require.ErrorIs(t, err, context.Canceled)
					require.False(t, active)
					return nil
				})
			}))
			active, err = r.AuthTransactionActive(retained)
			require.Error(t, err)
			require.False(t, active)
			require.EqualValues(t, 1, trace.begins.Load())
			require.Zero(t, trace.writes.Load())
		})
	}
}

func TestAuthTransactionActiveAfterRollback(t *testing.T) {
	r := ownedTransactionRuntime(t, &ownedTransactionTrace{})
	var retained context.Context
	rejection := errors.New("reject scope")
	require.ErrorIs(t, r.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		retained = ctx
		return rejection
	}), rejection)
	active, err := r.AuthTransactionActive(retained)
	require.Error(t, err)
	require.False(t, active)
	var absent *Runtime
	active, err = absent.AuthTransactionActive(t.Context())
	require.Error(t, err)
	require.False(t, active)
}
