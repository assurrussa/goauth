//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

// Keep real PostgreSQL queries and transactions, replacing only one commit
// response. Both durable-commit and durable-rollback variants must be treated as
// unknown by the caller, and resolved by the host receipt, never a blind retry.
type renameCommitFault struct {
	armed  atomic.Bool
	commit bool
}

type renameFaultConnector struct {
	driver.Connector
	fault *renameCommitFault
}

func (c renameFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	pgconn, ok := conn.(*stdlib.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected integration connector connection %T", conn)
	}
	return &renameFaultConn{Conn: pgconn, fault: c.fault}, nil
}

type renameFaultConn struct {
	*stdlib.Conn
	fault *renameCommitFault
}

func (c *renameFaultConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return renameFaultTx{Tx: tx, fault: c.fault}, nil
}

type renameFaultTx struct {
	driver.Tx
	fault *renameCommitFault
}

func (tx renameFaultTx) Commit() error {
	if !tx.fault.armed.CompareAndSwap(true, false) {
		return tx.Tx.Commit()
	}
	var err error
	if tx.fault.commit {
		err = tx.Tx.Commit()
	} else {
		err = tx.Tx.Rollback()
	}
	if err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}

func TestPostgresLocalIdentityRenameUnknownCommitDoesNotClaimSuccess(t *testing.T) {
	for _, committed := range []bool{true, false} {
		for _, outer := range []bool{true, false} {
			name := map[bool]string{true: "committed", false: "rolled-back"}[committed] + "/" + map[bool]string{true: "outer-receipt", false: "direct"}[outer]
			t.Run(name, func(t *testing.T) {
				observerDB := integrationDB(t)
				resetSchema(t, observerDB)
				config, err := pgx.ParseConfig(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
				require.NoError(t, err)
				fault := &renameCommitFault{commit: committed}
				db := sql.OpenDB(renameFaultConnector{Connector: stdlib.GetConnector(*config), fault: fault})
				t.Cleanup(func() { require.NoError(t, db.Close()) })
				runtime := renamePostgresRuntime(t, db, nil)
				fixture := seedRenameSecurity(t, observerDB, runtime)
				id := fixture.registered.Account.Subject.ID
				before := renameIdentitySnapshot(t, observerDB, id)
				_, err = observerDB.Exec(`CREATE TABLE rename_outcome_receipt (subject_id uuid PRIMARY KEY, security_version bigint NOT NULL)`)
				require.NoError(t, err)
				t.Cleanup(func() { _, err := observerDB.Exec(`DROP TABLE rename_outcome_receipt`); require.NoError(t, err) })
				request := renameRequest(fixture.registered.Account, "SecurityOriginal", "SecurityRenamed")
				var view goauth.LocalIdentityView
				fault.armed.Store(true)
				if outer {
					err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
						var err error
						view, err = runtime.RenameLocalIdentity(ctx, request)
						if err != nil {
							return err
						}
						executor, err := runtime.SQLExecutor(ctx)
						if err != nil {
							return err
						}
						_, err = executor.ExecContext(ctx, `INSERT INTO rename_outcome_receipt VALUES($1,$2)`, id, view.Account.Subject.SecurityVersion)
						return err
					})
					require.NotZero(t, view, "the nested view is provisional, so callers must inspect the outer outcome")
				} else {
					view, err = runtime.RenameLocalIdentity(t.Context(), request)
					require.Zero(t, view, "an uncertain own commit must never return a successful view")
				}
				require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
				require.False(t, fault.armed.Load(), "the intended transaction must reach the injected commit")
				var receipts int
				require.NoError(t, observerDB.QueryRow(`SELECT count(*) FROM rename_outcome_receipt WHERE subject_id=$1`, id).Scan(&receipts))
				if committed {
					identifier, err := runtime.GetLocalIdentifier(t.Context(), id, postgresIdentityScheme)
					require.NoError(t, err)
					require.Equal(t, "SecurityRenamed", identifier.NormalizedValue)
					stored, err := runtime.GetAccount(t.Context(), id)
					require.NoError(t, err)
					require.Equal(t, request.ExpectedSecurityVersion+1, stored.Subject.SecurityVersion)
					require.Equal(t, 1, renameAuditCount(t, observerDB, id))
					assertTrustedPasswordInvalidated(t, observerDB, id)
					if outer {
						require.Equal(t, 1, receipts)
					} else {
						require.Zero(t, receipts)
					}
				} else {
					require.Zero(t, receipts)
					require.Equal(t, before, renameIdentitySnapshot(t, observerDB, id))
				}
			})
		}
	}
}
