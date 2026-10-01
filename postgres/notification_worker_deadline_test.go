package postgres //nolint:testpackage // Exercise worker deadlines and SQL lease ownership through a driver.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	deadlineBeforeSend         = "before_send"
	deadlineReservationTimeout = "reservation_timeout"
	deadlineSenderFailure      = "sender_failure"
)

type deadlineDelivery struct {
	event    goauth.EncryptedEvent
	token    string
	attempts int64
	state    string
}

type deadlineDriver struct {
	deliveries     []deadlineDelivery
	mode           string
	cancel         context.CancelFunc
	reserveErr     error
	finishErr      error
	budgetErr      error
	secondFinished chan struct{}
}

type (
	deadlineConn struct{ state *deadlineDriver }
	deadlineRows struct{ values []driver.Value }
)

func (d *deadlineDriver) Open(string) (driver.Conn, error) { return &deadlineConn{state: d}, nil }
func (*deadlineConn) Prepare(string) (driver.Stmt, error)  { return nil, errors.New("unused prepare") }

func (*deadlineConn) Begin() (driver.Tx, error) { return nil, errors.New("unused begin") }
func (*deadlineConn) Close() error              { return nil }
func (r *deadlineRows) Columns() []string {
	columns := make([]string, len(r.values))
	for i := range columns {
		columns[i] = strconv.Itoa(i)
	}
	return columns
}
func (*deadlineRows) Close() error { return nil }
func (r *deadlineRows) Next(values []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(values, r.values)
	r.values = nil
	return nil
}

func (c *deadlineConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "RETURNING id, subject_id") {
		for i := range c.state.deliveries {
			d := &c.state.deliveries[i]
			if d.state != "" {
				continue
			}
			d.state = notificationLeased
			token, ok := args[1].Value.(string)
			if !ok {
				return nil, errors.New("invalid lease token")
			}
			d.token = token
			e := d.event
			return &deadlineRows{values: []driver.Value{
				e.ID, e.SubjectID.String(), e.Type, e.ReferenceID, e.ValidUntil, e.Envelope.KeyID,
				e.Envelope.Nonce, e.Envelope.Ciphertext, e.Envelope.AdditionalData,
				e.Envelope.CreatedAt, e.Envelope.DeleteAfter, d.attempts,
			}}, nil
		}
		return &deadlineRows{}, nil
	}
	if strings.Contains(query, "SELECT attempts") {
		if c.state.budgetErr != nil {
			return nil, c.state.budgetErr
		}
		for i := range c.state.deliveries {
			d := &c.state.deliveries[i]
			if d.event.ID == args[0].Value && d.token == args[1].Value && d.state == notificationLeased {
				return &deadlineRows{values: []driver.Value{d.attempts}}, nil
			}
		}
		return &deadlineRows{}, nil
	}
	return nil, fmt.Errorf("unexpected query: %s", query)
}

func (c *deadlineConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	for i := range c.state.deliveries {
		d := &c.state.deliveries[i]
		if d.event.ID != args[0].Value || d.token != args[1].Value || d.state != notificationLeased {
			continue
		}
		if strings.Contains(query, "SET attempts = attempts + 1") {
			return c.reserve(ctx, i)
		}
		if strings.Contains(query, "SET state = $3") {
			if c.state.finishErr != nil {
				return nil, c.state.finishErr
			}
			state, ok := args[2].Value.(string)
			if !ok {
				return nil, errors.New("invalid delivery state")
			}
			d.state = state
			d.token = ""
			if i == 1 && c.state.secondFinished != nil {
				close(c.state.secondFinished)
			}
			return driver.RowsAffected(1), nil
		}
	}
	return driver.RowsAffected(0), nil
}

func (c *deadlineConn) reserve(ctx context.Context, i int) (driver.Result, error) {
	d := &c.state.deliveries[i]
	if i == 0 {
		if c.state.reserveErr != nil {
			if c.state.mode == "storage_timeout" {
				<-ctx.Done()
			}
			return nil, c.state.reserveErr
		}
		switch c.state.mode {
		case deadlineBeforeSend:
			d.attempts++
			<-ctx.Done()
			return driver.RowsAffected(1), nil
		case "reservation_committed":
			d.attempts++
			<-ctx.Done()
			return nil, ctx.Err()
		case deadlineReservationTimeout:
			<-ctx.Done()
			return nil, ctx.Err()
		case "pg_query_cancelled":
			<-ctx.Done()
			return nil, &pgconn.PgError{Code: "57014"}
		case "parent_cancel":
			c.state.cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		case "lease_lost":
			d.token = "new-owner"
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}
	d.attempts++
	return driver.RowsAffected(1), nil
}

func deadlineEvent(t *testing.T, id string, validUntil time.Time) goauth.EncryptedEvent {
	t.Helper()
	subjectID, err := goauth.ParseSubjectID(uuid.NewString())
	require.NoError(t, err)
	event := goauth.EncryptedEvent{ID: id, Type: "worker_test", SubjectID: subjectID, ValidUntil: validUntil}
	aad := []byte("goauth-notification:v1:" + strconv.Quote(id) + ":" + strconv.Quote(event.Type) + ":" +
		strconv.Quote(subjectID.String()) + ":" + strconv.Quote("") + ":" +
		strconv.FormatInt(validUntil.UTC().UnixMicro(), 10))
	key := make([]byte, 32)
	for i := range key {
		key[i] = 3
	}
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	event.Envelope = goauth.EncryptedEnvelope{
		KeyID: "outbox-v1", Nonce: nonce, AdditionalData: aad, CreatedAt: time.Now(), DeleteAfter: validUntil.Add(time.Hour),
		Ciphertext: aead.Seal(nil, nonce, []byte(`{"template":"test","to":"worker@example.test"}`), aad),
	}
	return event
}

func deadlineRuntime(t *testing.T, d *deadlineDriver, sender goauth.NotificationSender) *Runtime {
	t.Helper()
	name := "goauth-worker-deadline-" + uuid.NewString()
	sql.Register(name, d)
	db, err := sql.Open(name, "")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	return &Runtime{
		Runtime: fixture.Runtime, store: &Store{db: db}, notificationSender: sender, notificationNow: time.Now,
		notificationWorker: NotificationWorkerConfig{
			Workers: 1, PollInterval: 10 * time.Millisecond, SendTimeout: 20 * time.Millisecond,
			LeaseDuration: time.Second, RetryMin: time.Second, RetryMax: time.Second, MaxAttempts: 2,
		},
	}
}

func TestNotificationChildDeadlineKeepsWorkerRunning(t *testing.T) {
	for _, tc := range []struct {
		name, mode, state            string
		expiry, committed, exhausted bool
	}{
		{name: "expires before sender", mode: deadlineBeforeSend, state: notificationExpired, expiry: true, committed: true},
		{name: "expires during reservation", mode: deadlineReservationTimeout, state: notificationExpired, expiry: true},
		{name: "reservation timeout retries", mode: deadlineReservationTimeout, state: notificationPending},
		{name: "PostgreSQL query cancellation retries", mode: "pg_query_cancelled", state: notificationPending},
		{
			name: "committed reservation timeout exhausts", mode: "reservation_committed",
			state: notificationExhausted, committed: true, exhausted: true,
		},
		{name: "send timeout before sender retries", mode: deadlineBeforeSend, state: notificationPending, committed: true},
		{name: "timeout after lease takeover", mode: "lease_lost", state: notificationLeased},
		{name: "sender failure retries", mode: deadlineSenderFailure, state: notificationPending, committed: true},
		{name: "sender failure exhausts", mode: deadlineSenderFailure, state: notificationExhausted, committed: true, exhausted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			until := time.Now().Add(time.Hour)
			d := &deadlineDriver{mode: tc.mode, secondFinished: make(chan struct{}), deliveries: []deadlineDelivery{
				{event: deadlineEvent(t, "first", until)}, {event: deadlineEvent(t, "second", time.Now().Add(time.Hour))},
			}}
			if tc.exhausted {
				d.deliveries[0].attempts = 1
			}
			sent := make(chan string, 2)
			r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(_ context.Context, delivery goauth.NotificationDelivery) error {
				if delivery.ID == "first" && tc.mode == deadlineSenderFailure {
					return context.DeadlineExceeded
				}
				sent <- delivery.ID
				return nil
			}))
			if tc.expiry {
				r.notificationWorker.SendTimeout = 200 * time.Millisecond
				d.deliveries[0].event = deadlineEvent(t, "first", time.Now().Add(100*time.Millisecond))
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.RunNotifications(ctx) }()
			select {
			case id := <-sent:
				require.Equal(t, "second", id)
			case err := <-done:
				t.Fatalf("worker stopped before second delivery: %v", err)
			case <-time.After(time.Second):
				t.Fatal("second delivery was not sent")
			}
			select {
			case <-d.secondFinished:
			case err := <-done:
				t.Fatalf("worker stopped before second completion: %v", err)
			case <-time.After(time.Second):
				t.Fatal("second completion missing")
			}
			cancel()
			require.NoError(t, <-done)
			require.Equal(t, tc.state, d.deliveries[0].state)
			attempts := int64(0)
			if tc.committed {
				attempts++
			}
			if tc.exhausted {
				attempts++
			}
			require.Equal(t, attempts, d.deliveries[0].attempts)
		})
	}
}

func TestNotificationParentCancellationDuringReservationStopsWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &deadlineDriver{mode: "parent_cancel", cancel: cancel, deliveries: []deadlineDelivery{
		{event: deadlineEvent(t, "first", time.Now().Add(time.Hour))},
		{event: deadlineEvent(t, "second", time.Now().Add(time.Hour))},
	}}
	r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		t.Error("sender called after parent cancellation")
		return nil
	}))
	require.NoError(t, r.RunNotifications(ctx))
	require.Equal(t, notificationLeased, d.deliveries[0].state)
	require.Empty(t, d.deliveries[1].state)
	require.Zero(t, d.deliveries[0].attempts)
}

func TestNotificationStorageFailureStillStopsWorker(t *testing.T) {
	for _, stage := range []string{"reservation", "reservation after deadline", "budget", "completion"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("storage unavailable")
			d := &deadlineDriver{mode: deadlineReservationTimeout, deliveries: []deadlineDelivery{
				{event: deadlineEvent(t, "first", time.Now().Add(time.Hour))},
				{event: deadlineEvent(t, "second", time.Now().Add(time.Hour))},
			}}
			switch stage {
			case "reservation":
				d.reserveErr = failure
			case "reservation after deadline":
				d.reserveErr = failure
				d.mode = "storage_timeout"
			case "budget":
				d.budgetErr = failure
			case "completion":
				d.finishErr = failure
			}
			r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
				t.Error("sender called after storage failure")
				return nil
			}))
			require.ErrorIs(t, r.RunNotifications(context.Background()), failure)
			require.Empty(t, d.deliveries[1].state)
		})
	}
}
