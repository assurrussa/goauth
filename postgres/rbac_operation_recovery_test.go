package postgres //nolint:testpackage // Exercise savepoint failure outcomes through a controlled SQL driver.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type (
	rbacRecoveryDriver struct{ failure string }
	rbacRecoveryConn   struct {
		notificationRecordingConn
		failure string
	}
)

func (d rbacRecoveryDriver) Open(string) (driver.Conn, error) {
	return &rbacRecoveryConn{failure: d.failure}, nil
}

func (c *rbacRecoveryConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if query == c.failure {
		return nil, errors.New("savepoint unavailable")
	}
	if strings.Contains(query, "INSERT INTO auth_subject_roles") {
		return driver.RowsAffected(0), nil // A handled missing-role business error.
	}
	return driver.RowsAffected(1), nil
}

func TestManagedRBACRecoveryFailureCannotCommit(t *testing.T) {
	for _, failure := range []string{
		"SAVEPOINT goauth_rbac_operation",
		"ROLLBACK TO SAVEPOINT goauth_rbac_operation",
		"RELEASE SAVEPOINT goauth_rbac_operation",
	} {
		t.Run(failure, func(t *testing.T) {
			name := "goauth-rbac-recovery-" + uuid.NewString()
			sql.Register(name, rbacRecoveryDriver{failure: failure})
			db, err := sql.Open(name, "")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			delegate := &recoveryCache{}
			cache := &transactionCache{db: db, delegate: delegate, invalidator: delegate}
			management := &rbacStore{db: db, cache: cache}
			err = (&Store{db: db}).InAuthTransaction(t.Context(), func(ctx context.Context) error {
				require.Error(t, management.AssignRole(ctx, goauth.NewSubjectID(), "missing"))
				return nil // Handling the error cannot commit an unrecovered operation.
			})
			require.ErrorIs(t, err, sql.ErrTxDone)
			require.NotErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
			require.Zero(t, cache.pending)
			require.False(t, cache.uncertain)
			_, found, readErr := cache.HasPermission(t.Context(), goauth.NewSubjectID(), "users:read")
			require.NoError(t, readErr)
			require.True(t, found, "aborted transaction restores unchanged cache trust")
		})
	}
}

func TestManagedRBACCanceledOperationDoesNotAbortOuterTransaction(t *testing.T) {
	db := openNotificationRecordingDB(t, "child-rbac-cancellation")
	delegate := &recoveryCache{}
	cache := &transactionCache{db: db, delegate: delegate, invalidator: delegate}
	management := &rbacStore{db: db, cache: cache}
	require.NoError(t, (&Store{db: db}).InAuthTransaction(t.Context(), func(ctx context.Context) error {
		child, cancel := context.WithCancel(ctx)
		cancel()
		require.ErrorIs(t, management.AssignRole(child, goauth.NewSubjectID(), "operator"), context.Canceled)
		require.Zero(t, cache.pending, "a canceled operation must not start a write")
		return management.AssignRole(ctx, goauth.NewSubjectID(), "operator")
	}))
	require.Zero(t, cache.pending)
}
