package postgres //nolint:testpackage // Exercise private transaction propagation across Store instances.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"testing"
)

type (
	notificationRecordingDriver struct{}
	notificationRecordingConn   struct{ name string }
	notificationRecordingTx     struct{}
)

var notificationTrace struct {
	sync.Mutex
	writes []string
}

var registerNotificationRecordingDriver sync.Once

func (notificationRecordingDriver) Open(name string) (driver.Conn, error) {
	return &notificationRecordingConn{name: name}, nil
}

func (*notificationRecordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}

func (*notificationRecordingConn) Close() error { return nil }

func (*notificationRecordingConn) Begin() (driver.Tx, error) {
	return notificationRecordingTx{}, nil
}

func (*notificationRecordingConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return notificationRecordingTx{}, nil
}

func (notificationRecordingTx) Commit() error   { return nil }
func (notificationRecordingTx) Rollback() error { return nil }

func (c *notificationRecordingConn) ExecContext(
	_ context.Context,
	query string,
	_ []driver.NamedValue,
) (driver.Result, error) {
	notificationTrace.Lock()
	defer notificationTrace.Unlock()
	notificationTrace.writes = append(notificationTrace.writes, c.name+":"+query)
	return driver.RowsAffected(1), nil
}

func openNotificationRecordingDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	registerNotificationRecordingDriver.Do(func() {
		sql.Register("goauth-notification-transaction-test", notificationRecordingDriver{})
	})
	db, err := sql.Open("goauth-notification-transaction-test", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func resetNotificationTrace() {
	notificationTrace.Lock()
	defer notificationTrace.Unlock()
	notificationTrace.writes = nil
}

func notificationWrites() []string {
	notificationTrace.Lock()
	defer notificationTrace.Unlock()
	return append([]string(nil), notificationTrace.writes...)
}

func TestNotificationTransactionRejectsForeignDBHandle(t *testing.T) {
	dbA := openNotificationRecordingDB(t, "database-A")
	dbB := openNotificationRecordingDB(t, "database-B")
	storeA, storeB := &Store{db: dbA}, &Store{db: dbB}
	resetNotificationTrace()

	err := storeA.InNotificationTransaction(context.Background(), func(ctx context.Context) error {
		nestedCalled := false
		nestedErr := storeB.InNotificationTransaction(ctx, func(context.Context) error {
			nestedCalled = true
			return nil
		})
		if !errors.Is(nestedErr, errForeignNotificationTransaction) || nestedCalled {
			t.Fatalf("foreign transaction callback: err=%v called=%v", nestedErr, nestedCalled)
		}
		if _, _, err := storeB.beginWrite(ctx); !errors.Is(err, errForeignNotificationTransaction) {
			t.Fatalf("foreign beginWrite error = %v", err)
		}
		_, err := storeB.notificationExecer(ctx).ExecContext(ctx, "intended-for-B")
		if !errors.Is(err, errForeignNotificationTransaction) {
			t.Fatalf("foreign notificationExecer error = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if writes := notificationWrites(); len(writes) != 0 {
		t.Fatalf("foreign store wrote using another DB handle: %v", writes)
	}
}

func TestNotificationTransactionReusesSameDBHandle(t *testing.T) {
	db := openNotificationRecordingDB(t, "database-A")
	storeA, storeB := &Store{db: db}, &Store{db: db}
	resetNotificationTrace()

	err := storeA.InNotificationTransaction(context.Background(), func(ctx context.Context) error {
		return storeB.InNotificationTransaction(ctx, func(nested context.Context) error {
			tx, owned, err := storeB.beginWrite(nested)
			if err != nil || owned || tx == nil {
				t.Fatalf("shared beginWrite: tx=%v owned=%v err=%v", tx, owned, err)
			}
			_, err = storeB.notificationExecer(nested).ExecContext(nested, "intended-for-A")
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if writes := notificationWrites(); len(writes) != 1 || writes[0] != "database-A:intended-for-A" {
		t.Fatalf("same-handle transaction writes = %v", writes)
	}
}

func TestNotificationTransactionReusesSameStore(t *testing.T) {
	db := openNotificationRecordingDB(t, "database-A")
	store := &Store{db: db}
	resetNotificationTrace()

	err := store.InNotificationTransaction(context.Background(), func(ctx context.Context) error {
		return store.InNotificationTransaction(ctx, func(nested context.Context) error {
			_, err := store.notificationExecer(nested).ExecContext(nested, "same-store-write")
			return err
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if writes := notificationWrites(); len(writes) != 1 || writes[0] != "database-A:same-store-write" {
		t.Fatalf("same-store transaction writes = %v", writes)
	}
}
