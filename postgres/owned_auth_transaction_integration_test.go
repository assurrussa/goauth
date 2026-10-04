//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestOwnedAuthTransactionPostgresBoundary(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.NotificationDelivery = goauth.NotificationDeliveryDisabled
	config.OutboxAEADKeys = goauth.KeyRing{}
	config.URLBuilder = nil
	runtime, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	alias, err := postgres.NewRuntime(postgres.Config{DB: db, Runtime: config})
	require.NoError(t, err)
	foreignDB := integrationDB(t)
	require.NotSame(t, db, foreignDB)
	foreign, err := postgres.NewRuntime(postgres.Config{DB: foreignDB, Runtime: config})
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "CREATE TABLE goauth_owned_probe (value integer UNIQUE DEFERRABLE INITIALLY DEFERRED)")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE goauth_owned_probe") })
	for _, outer := range []func(context.Context, func(context.Context) error) error{
		runtime.InAuthTransaction, runtime.InOwnedAuthTransaction,
	} {
		require.NoError(t, outer(t.Context(), func(ctx context.Context) error {
			for _, nested := range []*postgres.Runtime{runtime, alias, foreign} {
				called := false
				nestedErr := nested.InOwnedAuthTransaction(ctx, func(context.Context) error { called = true; return nil })
				require.False(t, called)
				if nested == foreign {
					require.Error(t, nestedErr)
					require.NotErrorIs(t, nestedErr, postgres.ErrAuthTransactionAlreadyActive)
				} else {
					require.ErrorIs(t, nestedErr, postgres.ErrAuthTransactionAlreadyActive)
				}
			}
			return nil
		}))
	}
	for _, name := range []string{
		ownedPostgresCommitted, ownedPostgresRolledBack, ownedPostgresCancelled, ownedPostgresCommitRejected,
	} {
		t.Run(name, func(t *testing.T) { testOwnedPostgresOutcome(t, runtime, alias, name) })
	}
}

const (
	ownedPostgresCancelled      = "request cancelled"
	ownedPostgresCommitted      = "commit"
	ownedPostgresRolledBack     = "rollback"
	ownedPostgresCommitRejected = "rejected commit"
)

func testOwnedPostgresOutcome(t *testing.T, runtime, alias *postgres.Runtime, name string) {
	t.Helper()
	db := runtime.Database()
	rejection := errors.New("host rollback")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	prepared := ""
	callbackCompleted := false
	err := runtime.InOwnedAuthTransaction(ctx, func(txctx context.Context) error {
		if err := alias.InAuthTransaction(txctx, func(nested context.Context) error {
			executor, err := alias.SQLExecutor(nested)
			if err != nil {
				return err
			}
			_, err = executor.ExecContext(nested, "INSERT INTO goauth_owned_probe(value) VALUES (1)")
			return err
		}); err != nil {
			return err
		}
		var visible int
		require.NoError(t, db.QueryRowContext(txctx, "SELECT count(*) FROM goauth_owned_probe").Scan(&visible))
		require.Zero(t, visible, "legacy join must not commit early")
		prepared = "provisional-token"
		switch name {
		case ownedPostgresRolledBack:
			return rejection
		case ownedPostgresCancelled:
			cancel()
			return ctx.Err()
		case ownedPostgresCommitRejected:
			executor, err := runtime.SQLExecutor(txctx)
			if err != nil {
				return err
			}
			_, err = executor.ExecContext(txctx, "INSERT INTO goauth_owned_probe(value) VALUES (1)")
			if err != nil {
				return err
			}
		}
		callbackCompleted = true
		return nil
	})
	response := ""
	if err == nil {
		response = prepared
	}
	if name == ownedPostgresCommitted {
		require.NoError(t, err)
		require.Equal(t, "provisional-token", response)
	} else {
		require.Error(t, err)
		require.Empty(t, response)
		require.NotErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
		switch name {
		case ownedPostgresRolledBack:
			require.ErrorIs(t, err, rejection)
		case ownedPostgresCancelled:
			require.ErrorIs(t, err, context.Canceled)
		case ownedPostgresCommitRejected:
			require.NotErrorIs(t, err, sql.ErrTxDone)
			require.True(t, callbackCompleted, "both deferred writes must complete before commit rejection")
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "23505", pgErr.Code)
		}
	}
	var count int
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM goauth_owned_probe").Scan(&count))
	if name == ownedPostgresCommitted {
		require.Equal(t, 1, count)
	} else {
		require.Zero(t, count)
	}
	_, err = db.ExecContext(t.Context(), "DELETE FROM goauth_owned_probe")
	require.NoError(t, err)
}
