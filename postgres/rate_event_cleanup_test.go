//nolint:testpackage // Verify validation before SQL and injected transaction outcomes.
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

func TestRateEventCleanupRejectsBeforeSQL(t *testing.T) {
	now := time.Date(2050, 1, 2, 12, 0, 0, 0, time.UTC)
	db := new(sql.DB) // Unusable: touching SQL would panic.
	r := &Runtime{db: db, store: &Store{db: db}, notificationNow: func() time.Time { return now }}
	for _, request := range []RateLimitCleanupRequest{
		{},
		{Limit: -1},
		{Limit: 1001},
		{Limit: 1, Before: now},
		{Limit: 1, Before: now.Add(time.Hour)},
		{Limit: 1, Before: now.Add(-24*time.Hour + time.Nanosecond)},
	} {
		count, err := r.CleanupRateLimitEvents(t.Context(), request)
		require.Error(t, err)
		require.Zero(t, count)
	}
	for _, invalid := range []*Runtime{nil, {}, {db: db}, {db: db, store: r.store}} {
		count, err := invalid.CleanupRateLimitEvents(t.Context(), RateLimitCleanupRequest{Limit: 1})
		require.Error(t, err)
		require.Zero(t, count)
	}
	for _, owner := range []*sql.DB{db, new(sql.DB)} {
		ctx := context.WithValue(t.Context(), notificationTxContextKey{}, notificationTxScope{db: owner, tx: new(sql.Tx)})
		count, err := r.CleanupRateLimitEvents(ctx, RateLimitCleanupRequest{Limit: 1})
		require.Error(t, err)
		require.Zero(t, count)
		if owner != db {
			require.ErrorIs(t, err, errForeignNotificationTransaction)
		}
	}
	r.notificationNow = func() time.Time { return time.Time{} }
	count, err := r.CleanupRateLimitEvents(t.Context(), RateLimitCleanupRequest{Limit: 1})
	require.Error(t, err)
	require.Zero(t, count)
}

type cleanupDriver struct {
	beginErr, execErr, countErr, commitErr error
	begins, commits, rollbacks             int
	args                                   []driver.NamedValue
	query                                  string
}

type cleanupConn struct{ *cleanupDriver }

type cleanupTx struct{ *cleanupDriver }

type cleanupResult struct{ err error }

func (d *cleanupDriver) Connect(context.Context) (driver.Conn, error) { return &cleanupConn{d}, nil }
func (d *cleanupDriver) Driver() driver.Driver                        { return d }
func (d *cleanupDriver) Open(string) (driver.Conn, error)             { return d.Connect(context.Background()) }

func (*cleanupConn) Prepare(string) (driver.Stmt, error)                            { return nil, errors.New("unused") }
func (*cleanupConn) Close() error                                                   { return nil }
func (c *cleanupConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c.Begin() }

func (c *cleanupConn) Begin() (driver.Tx, error) {
	c.begins++
	if c.beginErr != nil {
		return nil, c.beginErr
	}
	return &cleanupTx{c.cleanupDriver}, nil
}

func (c *cleanupConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.query, c.args = query, args
	if c.execErr != nil {
		return nil, c.execErr
	}
	return cleanupResult{c.countErr}, nil
}
func (t *cleanupTx) Commit() error                   { t.commits++; return t.commitErr }
func (t *cleanupTx) Rollback() error                 { t.rollbacks++; return nil }
func (cleanupResult) LastInsertId() (int64, error)   { return 0, errors.New("unused") }
func (r cleanupResult) RowsAffected() (int64, error) { return 3, r.err }

func TestRateEventCleanupClockAndCommittedCount(t *testing.T) {
	now := time.Date(2050, 1, 2, 12, 0, 0, 0, time.FixedZone("offset", 3600))
	for _, before := range []time.Time{{}, now.Add(-24 * time.Hour), now.Add(-72 * time.Hour)} {
		d := &cleanupDriver{}
		db := sql.OpenDB(d)
		t.Cleanup(func() { require.NoError(t, db.Close()) })
		r := &Runtime{db: db, store: &Store{db: db}, notificationNow: func() time.Time { return now }}
		count, err := r.CleanupRateLimitEvents(t.Context(), RateLimitCleanupRequest{Before: before, Limit: 1000})
		require.NoError(t, err)
		require.EqualValues(t, 3, count)
		require.Equal(t, 1, d.begins)
		require.Equal(t, 1, d.commits)
		require.Equal(t, rateEventCleanupSQL, d.query)
		if before.IsZero() {
			before = now.Add(-25 * time.Hour)
		}
		require.Equal(t, before.UTC(), d.args[0].Value)
		require.EqualValues(t, 1000, d.args[1].Value)
	}
}

func TestRateEventCleanupErrorsReturnZero(t *testing.T) {
	failure := errors.New("injected I/O failure")
	for _, test := range []struct {
		name    string
		driver  cleanupDriver
		unknown bool
	}{
		{"begin", cleanupDriver{beginErr: failure}, false},
		{"statement", cleanupDriver{execErr: failure}, false},
		{"count", cleanupDriver{countErr: failure}, false},
		{"unknown commit", cleanupDriver{commitErr: failure}, true},
		{"known commit rejection", cleanupDriver{commitErr: &pgconn.PgError{Code: "40001"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &test.driver
			db := sql.OpenDB(d)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			r := &Runtime{db: db, store: &Store{db: db}, notificationNow: time.Now}
			count, err := r.CleanupRateLimitEvents(t.Context(), RateLimitCleanupRequest{Limit: 3})
			require.Error(t, err)
			require.Zero(t, count)
			require.Equal(t, test.unknown, errors.Is(err, goauth.ErrOperationOutcomeUnknown))
			if d.execErr != nil || d.countErr != nil {
				require.Equal(t, 1, d.rollbacks)
				require.Zero(t, d.commits)
			}
		})
	}
}
