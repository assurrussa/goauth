package postgres //nolint:testpackage // Verify managed callback ownership with recording driver.

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestHostObserverOuterOutcome(t *testing.T) {
	for _, tc := range []struct {
		name         string
		commit, body error
		want         AuthTransactionOutcome
	}{
		{name: "commit", want: AuthTransactionCommitted},
		{name: "body rejection", body: errors.New("body rejected"), want: AuthTransactionRolledBack},
		{name: "transport uncertainty", commit: io.ErrUnexpectedEOF, want: AuthTransactionUnknown},
		{name: "pg statement unknown", commit: &pgconn.PgError{Code: "40003"}, want: AuthTransactionUnknown},
		{name: "pg transaction unknown", commit: &pgconn.PgError{Code: "08007"}, want: AuthTransactionUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ownedTransactionRuntime(t, &ownedTransactionTrace{commitErr: tc.commit})
			var got []AuthTransactionOutcome
			observer := &AuthTransactionObserver{Notify: func(o AuthTransactionOutcome) { got = append(got, o) }}
			require.Error(t, r.ObserveAuthTransaction(t.Context(), observer))
			var stale context.Context
			err := r.InAuthTransaction(t.Context(), func(ctx context.Context) error {
				stale = ctx
				require.NoError(t, r.ObserveAuthTransaction(ctx, observer))
				require.NoError(t, r.InAuthTransaction(ctx, func(child context.Context) error {
					return r.ObserveAuthTransaction(child, observer)
				}))
				require.Empty(t, got)
				return tc.body
			})
			if tc.commit != nil || tc.body != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, []AuthTransactionOutcome{tc.want}, got)
			require.Error(t, r.ObserveAuthTransaction(stale, observer))
		})
	}
}

func TestHostObserverForeignAndPanic(t *testing.T) {
	r := ownedTransactionRuntime(t, &ownedTransactionTrace{})
	other := ownedTransactionRuntime(t, &ownedTransactionTrace{})
	calls := 0
	observer := &AuthTransactionObserver{Notify: func(o AuthTransactionOutcome) {
		require.Equal(t, AuthTransactionRolledBack, o)
		calls++
	}}
	require.Panics(t, func() {
		_ = r.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			require.ErrorIs(t, other.ObserveAuthTransaction(ctx, observer), errForeignNotificationTransaction)
			require.Error(t, r.ObserveAuthTransaction(ctx, nil))
			require.NoError(t, r.ObserveAuthTransaction(ctx, observer))
			panic("body")
		})
	})
	require.Equal(t, 1, calls)
}

func TestHostObserverPanicDoesNotSkipRemainingOutcomes(t *testing.T) {
	r := ownedTransactionRuntime(t, &ownedTransactionTrace{})
	calls := 0
	require.Panics(t, func() {
		_ = r.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			require.NoError(t, r.ObserveAuthTransaction(ctx, &AuthTransactionObserver{Notify: func(AuthTransactionOutcome) {
				panic("observer")
			}}))
			require.NoError(t, r.ObserveAuthTransaction(ctx, &AuthTransactionObserver{Notify: func(o AuthTransactionOutcome) {
				require.Equal(t, AuthTransactionCommitted, o)
				calls++
			}}))
			scope, ok := ctx.Value(notificationTxContextKey{}).(notificationTxScope)
			require.True(t, ok)
			scope.callbacks.entries = append(scope.callbacks.entries, authTransactionCallback{afterCommit: func() { calls++ }})
			return nil
		})
	})
	require.Equal(t, 2, calls)
}
