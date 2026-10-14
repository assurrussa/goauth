//nolint:testpackage // Verify SQL routing, validation and injected transaction outcomes.
package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

const lifecycleDeliveryID = "00000000-0000-4000-8000-000000000001"

type lifecycleDriver struct {
	count                                 int64
	execErr, countErr, commitErr           error
	begins, commits, rollbacks, executions int
	query                                 string
	args                                  []driver.NamedValue
}

type lifecycleConn struct{ *lifecycleDriver }
type lifecycleTx struct{ *lifecycleDriver }
type lifecycleResult struct {
	count int64
	err   error
}

func (d *lifecycleDriver) Connect(context.Context) (driver.Conn, error) {
	return &lifecycleConn{d}, nil
}

func (d *lifecycleDriver) Driver() driver.Driver { return d }
func (d *lifecycleDriver) Open(string) (driver.Conn, error) {
	return d.Connect(context.Background())
}

func (*lifecycleConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}

func (*lifecycleConn) Close() error { return nil }
func (c *lifecycleConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.Begin()
}

func (c *lifecycleConn) Begin() (driver.Tx, error) {
	c.begins++
	return &lifecycleTx{c.lifecycleDriver}, nil
}

func (c *lifecycleConn) ExecContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	c.executions++
	c.query, c.args = query, args
	if c.execErr != nil {
		return nil, c.execErr
	}
	return lifecycleResult{c.count, c.countErr}, nil
}

func (tx *lifecycleTx) Commit() error   { tx.commits++; return tx.commitErr }
func (tx *lifecycleTx) Rollback() error { tx.rollbacks++; return nil }
func (lifecycleResult) LastInsertId() (int64, error) {
	return 0, errors.New("unused")
}

func (r lifecycleResult) RowsAffected() (int64, error) { return r.count, r.err }

func lifecycleRuntime(t *testing.T, d *lifecycleDriver) *Runtime {
	t.Helper()
	db := sql.OpenDB(d)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return &Runtime{
		db: db, store: &Store{db: db}, notificationWorker: NotificationWorkerConfig{MaxAttempts: 10},
		notificationNow: func() time.Time { return time.Date(2050, 1, 2, 12, 0, 0, 0, time.UTC) },
	}
}

func TestNotificationLifecycleRejectsBeforeSQL(t *testing.T) {
	d := &lifecycleDriver{}
	r := lifecycleRuntime(t, d)
	for _, id := range []string{"", "invalid", "00000000-0000-0000-0000-000000000000"} {
		changed, err := r.CancelNotification(t.Context(), id)
		require.Error(t, err)
		require.False(t, changed)
	}
	for _, request := range []struct {
		retention time.Duration
		limit     int
	}{
		{0, 0}, {0, -1}, {0, 1001}, {-time.Hour, 1}, {24*time.Hour - time.Nanosecond, 1},
	} {
		count, err := r.CleanupNotificationReceipts(t.Context(), request.retention, request.limit)
		require.Error(t, err)
		require.Zero(t, count)
	}
	for _, invalid := range []*Runtime{nil, {}, {store: r.store}, {store: &Store{}}} {
		changed, err := invalid.CancelNotification(t.Context(), lifecycleDeliveryID)
		require.Error(t, err)
		require.False(t, changed)
		count, err := invalid.CleanupNotificationReceipts(t.Context(), 0, 1)
		require.Error(t, err)
		require.Zero(t, count)
	}
	r.notificationNow = func() time.Time { return time.Time{} }
	changed, err := r.CancelNotification(t.Context(), lifecycleDeliveryID)
	require.Error(t, err)
	require.False(t, changed)
	count, err := r.CleanupNotificationReceipts(t.Context(), 0, 1)
	require.Error(t, err)
	require.Zero(t, count)
	require.Zero(t, d.begins)
	require.Zero(t, d.executions)
}

func TestNotificationCancellationUsesClockAndBudget(t *testing.T) {
	for _, affected := range []int64{0, 1} {
		d := &lifecycleDriver{count: affected}
		r := lifecycleRuntime(t, d)
		now := time.Date(2050, 1, 2, 12, 0, 0, 0, time.FixedZone("offset", 3600))
		samples := 0
		r.notificationNow = func() time.Time { samples++; return now }
		changed, err := r.CancelNotification(t.Context(), lifecycleDeliveryID)
		require.NoError(t, err)
		require.Equal(t, affected == 1, changed)
		require.Equal(t, notificationCancellationSQL, d.query)
		require.Equal(t, lifecycleDeliveryID, d.args[0].Value)
		require.Equal(t, now.UTC(), d.args[1].Value)
		require.EqualValues(t, 10, d.args[2].Value)
		require.Equal(t, 1, samples)
		require.Equal(t, 1, d.begins)
		require.Equal(t, 1, d.commits)
	}
}

func TestNotificationReceiptCleanupUsesRetentionAndBound(t *testing.T) {
	for _, retention := range []time.Duration{0, 24 * time.Hour, 30 * 24 * time.Hour} {
		d := &lifecycleDriver{count: 2}
		r := lifecycleRuntime(t, d)
		now := r.notificationNow()
		samples := 0
		r.notificationNow = func() time.Time { samples++; return now }
		count, err := r.CleanupNotificationReceipts(t.Context(), retention, 1000)
		require.NoError(t, err)
		require.EqualValues(t, 2, count)
		if retention == 0 {
			retention = 7 * 24 * time.Hour
		}
		require.Equal(t, notificationReceiptCleanupSQL, d.query)
		require.Equal(t, now.Add(-retention), d.args[0].Value)
		require.EqualValues(t, 1000, d.args[1].Value)
		require.Equal(t, 1, samples)
		require.Equal(t, 1, d.commits)
	}
}

func TestNotificationLifecycleJoinsManagedScopeAndRejectsForeignScope(t *testing.T) {
	d := &lifecycleDriver{count: 1}
	r := lifecycleRuntime(t, d)
	tx, err := r.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	ctx := context.WithValue(t.Context(), notificationTxContextKey{}, notificationTxScope{db: r.db, tx: tx})
	changed, err := r.CancelNotification(ctx, lifecycleDeliveryID)
	require.NoError(t, err)
	require.True(t, changed)
	count, err := r.CleanupNotificationReceipts(ctx, 0, 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	require.Equal(t, 1, d.begins)
	require.Zero(t, d.commits)
	require.Equal(t, 2, d.executions)

	foreign := context.WithValue(t.Context(), notificationTxContextKey{},
		notificationTxScope{db: new(sql.DB), tx: tx})
	changed, err = r.CancelNotification(foreign, lifecycleDeliveryID)
	require.ErrorIs(t, err, errForeignNotificationTransaction)
	require.False(t, changed)
	count, err = r.CleanupNotificationReceipts(foreign, 0, 1)
	require.ErrorIs(t, err, errForeignNotificationTransaction)
	require.Zero(t, count)
	require.Equal(t, 2, d.executions)
}

func TestNotificationLifecycleErrorsWithholdResults(t *testing.T) {
	failure := errors.New("injected I/O failure")
	for _, test := range []struct {
		name    string
		driver  lifecycleDriver
		unknown bool
	}{
		{"statement", lifecycleDriver{count: 1, execErr: failure}, false},
		{"count", lifecycleDriver{count: 1, countErr: failure}, false},
		{"unknown commit", lifecycleDriver{count: 1, commitErr: failure}, true},
		{"known commit", lifecycleDriver{count: 1, commitErr: &pgconn.PgError{Code: "40001"}}, false},
		{"out of bounds count", lifecycleDriver{count: 2}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := test.driver
			r := lifecycleRuntime(t, &d)
			changed, err := r.CancelNotification(t.Context(), lifecycleDeliveryID)
			require.Error(t, err)
			require.False(t, changed)
			require.Equal(t, test.unknown, errors.Is(err, goauth.ErrOperationOutcomeUnknown))
			d = test.driver
			count, err := r.CleanupNotificationReceipts(t.Context(), 0, 1)
			require.Error(t, err)
			require.Zero(t, count)
			require.Equal(t, test.unknown, errors.Is(err, goauth.ErrOperationOutcomeUnknown))
		})
	}
}
