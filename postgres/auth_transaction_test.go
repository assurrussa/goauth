package postgres //nolint:testpackage // Exercise commit outcomes through database/sql.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type (
	commitResultDriver struct{ err error }
	commitResultConn   struct {
		notificationRecordingConn
		err error
	}
)
type commitResultTx struct{ err error }

func (d commitResultDriver) Open(string) (driver.Conn, error) {
	return &commitResultConn{err: d.err}, nil
}

func (c *commitResultConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return commitResultTx{err: c.err}, nil
}
func (t commitResultTx) Commit() error { return t.err }
func (commitResultTx) Rollback() error { return nil }

func TestAuthTransactionCommitOutcome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		commitErr error
		unknown   bool
	}{
		{"network loss", io.ErrUnexpectedEOF, true},
		{"server rejected commit", &pgconn.PgError{Code: "40001", Message: "serialization failure"}, false},
		{"successful commit", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			name := "goauth-commit-" + uuid.NewString()
			sql.Register(name, commitResultDriver{err: tc.commitErr})
			db, err := sql.Open(name, "")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			store, err := NewStore(db)
			require.NoError(t, err)
			err = store.InAuthTransaction(context.Background(), func(context.Context) error { return nil })
			require.Equal(t, tc.unknown, errors.Is(err, goauth.ErrOperationOutcomeUnknown))
			if tc.commitErr != nil {
				require.ErrorIs(t, err, tc.commitErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestPostgresRuntimeRejectsAuditOverride(t *testing.T) {
	t.Parallel()
	_, err := NewRuntime(Config{Runtime: goauth.Config{
		AuditSink: goauth.AuditSinkFunc(func(context.Context, goauth.SecurityEvent) error { return nil }),
	}})
	require.ErrorContains(t, err, "requires its local audit store")
}
