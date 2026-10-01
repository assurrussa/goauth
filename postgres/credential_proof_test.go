package postgres //nolint:testpackage // Construct a runtime-bound proof to test SQL error classification.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type (
	proofQueryDriver struct{ err error }
	proofQueryConn   struct {
		notificationRecordingConn
		err error
	}
)

type proofEmptyRows struct{}

func (d proofQueryDriver) Open(string) (driver.Conn, error) {
	return &proofQueryConn{err: d.err}, nil
}

func (c *proofQueryConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	if c.err != nil {
		return nil, c.err
	}
	return proofEmptyRows{}, nil
}

func (proofEmptyRows) Columns() []string         { return []string{"id"} }
func (proofEmptyRows) Close() error              { return nil }
func (proofEmptyRows) Next([]driver.Value) error { return io.EOF }

func TestCredentialProofSubjectLockErrorClassification(t *testing.T) {
	storageErr := errors.New("storage unavailable")
	for _, tc := range []struct {
		name           string
		queryErr, want error
	}{
		{"deleted subject", nil, goauth.ErrInvalidCredentials},
		{"storage failure", storageErr, storageErr},
		{"query deadline", context.DeadlineExceeded, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "goauth-proof-query-" + uuid.NewString()
			sql.Register(name, proofQueryDriver{err: tc.queryErr})
			db, err := sql.Open(name, "")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			store, err := NewStore(db)
			require.NoError(t, err)
			runtime := &Runtime{db: db, store: store}
			proof := &CredentialProof{
				runtime: runtime, expiresAt: time.Now().Add(time.Minute),
				account: goauth.Account{Subject: goauth.Subject{ID: goauth.NewSubjectID()}},
			}
			err = runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
				account, revalidateErr := runtime.RevalidateCredential(ctx, proof)
				require.Empty(t, account, "failed revalidation cannot produce an authenticated account")
				return revalidateErr
			})
			require.ErrorIs(t, err, tc.want)
			if tc.queryErr != nil {
				require.NotErrorIs(t, err, goauth.ErrInvalidCredentials)
				require.ErrorContains(t, err, "lock verified subject")
			} else {
				require.NotErrorIs(t, err, sql.ErrNoRows)
			}
		})
	}
}
