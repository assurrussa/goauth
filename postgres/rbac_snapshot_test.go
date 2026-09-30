package postgres //nolint:testpackage // Verify rejection before any managed snapshot query.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

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
