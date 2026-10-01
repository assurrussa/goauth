package postgres //nolint:testpackage // Verify rejection before any managed snapshot query.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

func TestRBACSnapshotRejectsManagedTransaction(t *testing.T) {
	db := openNotificationRecordingDB(t, "snapshot")
	store := &Store{db: db}
	management := &rbacStore{db: db}
	resetNotificationTrace()
	require.NoError(t, store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		snapshot, err := management.Snapshot(ctx)
		require.ErrorIs(t, err, rbac.ErrSnapshotTransactionUnsupported)
		require.Empty(t, snapshot)
		_, err = store.notificationExecer(ctx).ExecContext(ctx, "write-after-rejected-snapshot")
		return err
	}))
	require.Equal(t, []string{"snapshot:write-after-rejected-snapshot"}, notificationWrites())
	foreign := &rbacStore{db: openNotificationRecordingDB(t, "foreign-snapshot")}
	require.NoError(t, store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, err := foreign.Snapshot(ctx)
		require.ErrorIs(t, err, errForeignNotificationTransaction)
		return nil
	}))
}

type snapshotCommitDriver struct {
	err     error
	options *driver.TxOptions
	queries *int
}

type snapshotCommitConn struct {
	commitResultConn
	options *driver.TxOptions
	queries *int
}

func (d snapshotCommitDriver) Open(string) (driver.Conn, error) {
	return &snapshotCommitConn{commitResultConn: commitResultConn{err: d.err}, options: d.options, queries: d.queries}, nil
}

func (c *snapshotCommitConn) BeginTx(_ context.Context, options driver.TxOptions) (driver.Tx, error) {
	*c.options = options
	return commitResultTx{err: c.err}, nil
}

func (c *snapshotCommitConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	*c.queries++
	return emptySnapshotRows{}, nil
}

type emptySnapshotRows struct{}

func (emptySnapshotRows) Columns() []string         { return nil }
func (emptySnapshotRows) Close() error              { return nil }
func (emptySnapshotRows) Next([]driver.Value) error { return io.EOF }

func TestRBACSnapshotCommitFailureDoesNotPoisonCache(t *testing.T) {
	for _, commitErr := range []error{io.ErrUnexpectedEOF, context.DeadlineExceeded, nil} {
		var options driver.TxOptions
		queries := 0
		name := "goauth-snapshot-commit-" + uuid.NewString()
		sql.Register(name, snapshotCommitDriver{err: commitErr, options: &options, queries: &queries})
		db, err := sql.Open(name, "")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, db.Close()) })
		delegate := &recoveryCache{}
		cache := &transactionCache{db: db, delegate: delegate, invalidator: delegate}
		management := &rbacStore{db: db, cache: cache}
		permissions, err := rbac.New(management, cache)
		require.NoError(t, err)
		subject := goauth.NewSubjectID()
		require.True(t, permissions.Can(t.Context(), subject, "users:read"))
		_, err = management.Snapshot(t.Context())
		if commitErr == nil {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, commitErr)
			require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
		}
		require.True(t, options.ReadOnly)
		require.Equal(t, driver.IsolationLevel(sql.LevelRepeatableRead), options.Isolation)
		require.Equal(t, 4, queries)
		require.False(t, cache.uncertain, "a read-only commit cannot make cached permissions uncertain")
		require.True(t, permissions.Can(t.Context(), subject, "users:read"))
		require.Equal(t, 2, delegate.reads, "authorization must continue using the cache")
	}
}
