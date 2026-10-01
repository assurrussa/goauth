package postgres //nolint:testpackage // Exercise recovery through public services and overlapping transactions.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestManagedCacheRecoveryAfterOverlappingRollback(t *testing.T) {
	for _, rollbackFirst := range []bool{false, true} {
		name := map[bool]string{false: "recovery before rollback", true: "rollback before recovery"}[rollbackFirst]
		t.Run(name, func(t *testing.T) {
			db := openSharedCacheDB(t, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			calls := 0
			delegate := &controlledInvalidationCache{invalidate: func(context.Context) error {
				calls++
				if calls == 1 {
					return errors.New("temporary invalidation outage")
				}
				close(entered)
				<-release
				return nil
			}}
			writer, err := NewRBAC(db, delegate)
			require.NoError(t, err)
			reader, err := NewRBAC(db, delegate)
			require.NoError(t, err)
			subject := goauth.NewSubjectID()
			require.True(t, reader.Can(t.Context(), subject, "users:read"))
			require.NoError(t, writer.AssignRole(t.Context(), subject, "operator"))
			require.False(t, reader.Can(t.Context(), subject, "users:read"), "failed invalidation uses PostgreSQL")
			store := &Store{db: db}
			recoveryResult, recoveryDone := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(recoveryDone)
				recoveryResult <- store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
					return writer.AssignRole(ctx, subject, "operator")
				})
			}()
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); <-recoveryDone })
			select {
			case <-entered:
			case err := <-recoveryResult:
				t.Fatalf("recovery did not enter invalidation: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("recovery invalidation did not start")
			}
			reserved, rollback := make(chan struct{}), make(chan struct{})
			var rollbackOnce sync.Once
			rejected := errors.New("host rolled back the later write")
			laterResult, laterDone := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(laterDone)
				laterResult <- store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
					if err := writer.AssignRole(ctx, subject, "operator"); err != nil {
						return err
					}
					close(reserved)
					<-rollback
					return rejected
				})
			}()
			t.Cleanup(func() { rollbackOnce.Do(func() { close(rollback) }); <-laterDone })
			select {
			case <-reserved:
			case err := <-laterResult:
				t.Fatalf("later write did not reserve bypass: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("later write did not finish its operation")
			}
			if rollbackFirst {
				rollbackOnce.Do(func() { close(rollback) })
				require.ErrorIs(t, <-laterResult, rejected)
				require.False(t, reader.Can(t.Context(), subject, "users:read"), "recovery is still pending")
			}
			releaseOnce.Do(func() { close(release) })
			require.NoError(t, <-recoveryResult)
			if !rollbackFirst {
				require.False(t, reader.Can(t.Context(), subject, "users:read"), "later write is still pending")
				rollbackOnce.Do(func() { close(rollback) })
				require.ErrorIs(t, <-laterResult, rejected)
			}
			require.True(t, reader.Can(t.Context(), subject, "users:read"), "rollback cannot suppress completed cache recovery")
			require.Equal(t, 2, calls, "recovery must not require an extra RBAC write")
		})
	}
}
