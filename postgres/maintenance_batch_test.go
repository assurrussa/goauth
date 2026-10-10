//nolint:testpackage // Exercise invalid requests and classified phase outcomes without a database.
package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

const (
	batchFailureBegin     = "begin"
	batchFailureStatement = "statement"
	batchFailureCount     = "count"
	batchFailureCommit    = "commit"
)

func TestCleanupBatchRejectsBeforeSQL(t *testing.T) {
	db := new(sql.DB) // Any SQL use would panic.
	r := &Runtime{db: db, store: &Store{db: db}}
	for _, limit := range []int{-1, 0, 1001} {
		result, err := r.CleanupBatch(t.Context(), CleanupPolicy{}, limit)
		require.Error(t, err)
		require.Equal(t, CleanupBatchResult{}, result)
	}
	for _, policy := range []CleanupPolicy{
		{ExpiredRecordRetention: -time.Second},
		{RateEventRetention: 23 * time.Hour},
		{AuditEventRetention: 23 * time.Hour},
		{NotificationReceiptRetention: 23 * time.Hour},
		{Now: func() time.Time { return time.Time{} }},
	} {
		result, err := r.CleanupBatch(t.Context(), policy, 1)
		require.Error(t, err)
		require.Equal(t, CleanupBatchResult{}, result)
	}
	for _, invalid := range []*Runtime{nil, {}, {db: db}, {db: db, store: &Store{db: new(sql.DB)}}} {
		result, err := invalid.CleanupBatch(t.Context(), CleanupPolicy{}, 1)
		require.Error(t, err)
		require.Equal(t, CleanupBatchResult{}, result)
	}
	for _, owner := range []*sql.DB{db, new(sql.DB)} {
		ctx := context.WithValue(t.Context(), notificationTxContextKey{}, notificationTxScope{db: owner, tx: new(sql.Tx)})
		result, err := r.CleanupBatch(ctx, CleanupPolicy{}, 1)
		require.Equal(t, CleanupBatchResult{}, result)
		if owner == db {
			require.ErrorIs(t, err, ErrAuthTransactionAlreadyActive)
		} else {
			require.ErrorIs(t, err, errForeignNotificationTransaction)
		}
	}
}

func TestCleanupBatchPreservesPolicyDefaults(t *testing.T) {
	policy, err := normalizeBatchCleanupPolicy(CleanupPolicy{})
	require.NoError(t, err)
	defaults := DefaultCleanupPolicy()
	require.Equal(t, defaults.ExpiredRecordRetention, policy.ExpiredRecordRetention)
	require.Equal(t, defaults.RateEventRetention, policy.RateEventRetention)
	require.Equal(t, defaults.AuditEventRetention, policy.AuditEventRetention)
	require.Equal(t, defaults.NotificationReceiptRetention, policy.NotificationReceiptRetention)
	require.NotNil(t, policy.Now)
}

type batchCleanupDriver struct {
	phase, failPhase int
	failAt           string
	failure          error
	committed        []int
	rolledBack       []int
	queries          []string
	arguments        [][]driver.NamedValue
}

type (
	batchCleanupConn  struct{ *batchCleanupDriver }
	batchCleanupTx    struct{ *batchCleanupDriver }
	batchCleanupRows  struct{}
	batchCleanupCount struct{ err error }
)

func (d *batchCleanupDriver) Connect(context.Context) (driver.Conn, error) {
	return &batchCleanupConn{d}, nil
}
func (d *batchCleanupDriver) Driver() driver.Driver { return d }
func (d *batchCleanupDriver) Open(string) (driver.Conn, error) {
	return d.Connect(context.Background())
}
func (*batchCleanupConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*batchCleanupConn) Close() error                        { return nil }
func (c *batchCleanupConn) Begin() (driver.Tx, error) {
	c.phase++
	if err := c.fail(batchFailureBegin); err != nil {
		return nil, err
	}
	return &batchCleanupTx{c.batchCleanupDriver}, nil
}

func (c *batchCleanupConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Begin()
}

func (d *batchCleanupDriver) fail(at string) error {
	if d.phase == d.failPhase && d.failAt == at {
		return d.failure
	}
	return nil
}

func (c *batchCleanupConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.queries = append(c.queries, query)
	c.arguments = append(c.arguments, args)
	if err := c.fail(batchFailureStatement); err != nil {
		return nil, err
	}
	return batchCleanupCount{err: c.fail(batchFailureCount)}, nil
}

func (c *batchCleanupConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.queries = append(c.queries, query)
	c.arguments = append(c.arguments, args)
	if err := c.fail("query"); err != nil {
		return nil, err
	}
	return batchCleanupRows{}, nil
}

func (tx *batchCleanupTx) Commit() error {
	if err := tx.fail(batchFailureCommit); err != nil {
		return err
	}
	tx.committed = append(tx.committed, tx.phase)
	return nil
}

func (tx *batchCleanupTx) Rollback() error {
	tx.rolledBack = append(tx.rolledBack, tx.phase)
	return nil
}
func (batchCleanupRows) Columns() []string               { return []string{"id"} }
func (batchCleanupRows) Close() error                    { return nil }
func (batchCleanupRows) Next([]driver.Value) error       { return io.EOF }
func (batchCleanupCount) LastInsertId() (int64, error)   { return 0, errors.New("unused") }
func (r batchCleanupCount) RowsAffected() (int64, error) { return 2, r.err }

func batchCleanupTestRuntime(t *testing.T, d *batchCleanupDriver) *Runtime {
	t.Helper()
	db := sql.OpenDB(d)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return &Runtime{db: db, store: &Store{db: db}, notificationNow: func() time.Time {
		t.Fatal("CleanupBatch must use only the explicit cleanup policy clock")
		return time.Time{}
	}}
}

func TestCleanupBatchUsesSingleClockAndIndependentPhases(t *testing.T) {
	d := &batchCleanupDriver{}
	r := batchCleanupTestRuntime(t, d)
	now := time.Date(2050, 1, 2, 12, 0, 0, 0, time.FixedZone("offset", 3600))
	calls := 0
	result, err := r.CleanupBatch(t.Context(), CleanupPolicy{Now: func() time.Time { calls++; return now }}, 2)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Equal(t, []int{1, 2, 3, 4}, d.committed)
	require.Empty(t, d.rolledBack)
	require.EqualValues(t, 2, result.NotificationsExpired)
	require.EqualValues(t, 2, result.OIDCRequests)
	require.EqualValues(t, 2, result.OIDCCodes)
	require.EqualValues(t, 2, result.PasswordResets)
	require.EqualValues(t, 2, result.EmailChallenges)
	require.EqualValues(t, 2, result.EmailChanges)
	require.EqualValues(t, 2, result.RateEvents)
	require.EqualValues(t, 2, result.AuditEvents)
	require.EqualValues(t, 2, result.NotificationReceipts)
	require.Zero(t, result.RefreshTokens)
	require.Equal(t, now.UTC(), d.arguments[0][0].Value)
	for i, query := range d.queries {
		if query == rateEventCleanupSQL {
			require.Equal(t, now.UTC().Add(-25*time.Hour), d.arguments[i][0].Value)
		}
		require.EqualValues(t, 2, d.arguments[i][len(d.arguments[i])-1].Value)
	}
}

func TestCleanupBatchErrorsKeepOnlyEarlierConfirmedPhases(t *testing.T) {
	failure := errors.New("injected I/O failure")
	for phase := 1; phase <= 4; phase++ {
		for _, at := range []string{batchFailureBegin, batchFailureStatement, batchFailureCount, batchFailureCommit} {
			if phase == 3 && (at == batchFailureStatement || at == batchFailureCount) {
				continue // This fixture's canonical phase has no subjects.
			}
			t.Run(strconv.Itoa(phase)+"/"+at, func(t *testing.T) {
				d := &batchCleanupDriver{failPhase: phase, failAt: at, failure: failure}
				result, err := batchCleanupTestRuntime(t, d).CleanupBatch(t.Context(), CleanupPolicy{}, 2)
				require.ErrorIs(t, err, failure)
				require.Equal(t, at == batchFailureCommit, errors.Is(err, goauth.ErrOperationOutcomeUnknown))
				expected := CleanupBatchResult{}
				if phase > 1 {
					expected.NotificationsExpired = 2
				}
				if phase > 2 {
					expected.OIDCRequests, expected.OIDCCodes = 2, 2
				}
				require.Equal(t, expected, result)
				require.Len(t, d.committed, phase-1)
			})
		}
	}
	for _, phase := range []int{2, 3} {
		d := &batchCleanupDriver{failPhase: phase, failAt: "query", failure: failure}
		_, err := batchCleanupTestRuntime(t, d).CleanupBatch(t.Context(), CleanupPolicy{}, 2)
		require.ErrorIs(t, err, failure)
		require.Equal(t, []int{phase}, d.rolledBack)
	}
	d := &batchCleanupDriver{failPhase: 4, failAt: batchFailureCommit, failure: &pgconn.PgError{Code: "40001"}}
	result, err := batchCleanupTestRuntime(t, d).CleanupBatch(t.Context(), CleanupPolicy{}, 2)
	require.Error(t, err)
	require.NotErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Zero(t, result.PasswordResets)
	require.EqualValues(t, 2, result.NotificationsExpired)
}

func TestCleanupBatchCanceledBeforeSQL(t *testing.T) {
	d := &batchCleanupDriver{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := batchCleanupTestRuntime(t, d).CleanupBatch(ctx, CleanupPolicy{}, 1)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, CleanupBatchResult{}, result)
	require.Empty(t, d.queries)
}

func TestCleanupBatchCapsFamilyAndSubjectCandidatesAt32(t *testing.T) {
	d := &batchCleanupDriver{}
	_, err := batchCleanupTestRuntime(t, d).CleanupBatch(t.Context(), CleanupPolicy{}, 1000)
	require.NoError(t, err)
	// Notification, request, code, OIDC family, canonical subject, then generic.
	require.EqualValues(t, 1000, d.arguments[0][1].Value)
	require.EqualValues(t, 1000, d.arguments[1][1].Value)
	require.EqualValues(t, 1000, d.arguments[2][1].Value)
	require.EqualValues(t, 32, d.arguments[3][1].Value)
	require.EqualValues(t, 32, d.arguments[4][1].Value)
}
