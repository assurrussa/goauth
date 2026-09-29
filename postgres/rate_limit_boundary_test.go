//nolint:testpackage // Ensures scope rejection precedes any database/sql operation.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/assurrussa/goauth"
)

func TestRateLimitBoundaryRejectsBeforeDatabaseIO(t *testing.T) {
	// A zero-value DB/Tx cannot execute queries: rejection must only inspect scope.
	db := new(sql.DB)
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), notificationTxContextKey{}, notificationTxScope{db: db, tx: new(sql.Tx)})
	request := goauth.RateLimitRequest{
		Action: "boundary", Bucket: goauth.SecretDigest{KeyID: "test", Digest: make([]byte, 32)},
		Window: time.Hour, Limit: 2, Now: time.Now(),
	}
	for _, handle := range []*Store{store, {db: db}} {
		result, err := handle.TakeRateLimit(ctx, request)
		if !errors.Is(err, goauth.ErrRateLimitTransactionUnsupported) || result.Allowed {
			t.Fatalf("nested admission = %v, %v", result, err)
		}
	}
	foreign := &Store{db: new(sql.DB)}
	if _, err := foreign.TakeRateLimit(ctx, request); !errors.Is(err, errForeignNotificationTransaction) {
		t.Fatalf("foreign scope must retain its diagnostic: %v", err)
	}
}
