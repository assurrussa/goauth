//nolint:testpackage // Verifies original and working Store handles in a managed scope.
package testkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/assurrussa/goauth"
)

func boundaryRateRequest() goauth.RateLimitRequest {
	return goauth.RateLimitRequest{
		Action: "boundary", Bucket: goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{7}, 32)},
		Window: time.Hour, Limit: 2, Now: time.Date(2026, 9, 29, 12, 0, 0, 123456789, time.UTC),
	}
}

func requireBoundaryAdmission(t *testing.T, store *Store, request goauth.RateLimitRequest, allowed bool) {
	t.Helper()
	result, err := store.TakeRateLimit(context.Background(), request)
	if err != nil || result.Allowed != allowed {
		t.Fatalf("admission = %v, %v; want allowed=%t", result, err, allowed)
	}
}

func TestRateLimitBoundaryCommitAndRollback(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(fmt.Sprintf("rollback=%t", rollback), func(t *testing.T) {
			store := NewStore()
			request := boundaryRateRequest()
			requireBoundaryAdmission(t, store, request, true)
			rollbackErr := errors.New("rollback fixture")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- store.InAuthTransaction(ctx, func(txCtx context.Context) error {
					for _, handle := range []*Store{store, store.scoped(txCtx)} {
						result, err := handle.TakeRateLimit(txCtx, request)
						if !errors.Is(err, goauth.ErrRateLimitTransactionUnsupported) || result.Allowed {
							return errors.New("nested admission must reject the active scope")
						}
					}
					if rollback {
						return rollbackErr
					}
					return nil
				})
			}()
			select {
			case err := <-done:
				if (rollback && !errors.Is(err, rollbackErr)) || (!rollback && err != nil) {
					t.Fatalf("transaction = %v", err)
				}
			case <-ctx.Done():
				t.Fatal("nested admission waited for the outer transaction lock")
			}
			// Neither commit nor rollback may erase the prior attempt or consume
			// another one for a rejected composition. Same-time attempts stay distinct.
			requireBoundaryAdmission(t, store, request, true)
			requireBoundaryAdmission(t, store, request, false)
		})
	}
}

func TestRateLimitBoundaryConcurrentSnapshotCannotLoseAttempts(t *testing.T) {
	store := NewStore()
	request := boundaryRateRequest()
	request.Limit = 10
	var successes atomic.Int64
	var failures atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range 40 {
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			result, err := store.TakeRateLimit(context.Background(), request)
			if err != nil {
				failures.Add(1)
			} else if result.Allowed {
				successes.Add(1)
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			if err := store.InAuthTransaction(context.Background(), func(context.Context) error { return nil }); err != nil {
				failures.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != 10 || failures.Load() != 0 {
		t.Fatalf("admitted=%d errors=%d; want 10 and 0", successes.Load(), failures.Load())
	}
	requireBoundaryAdmission(t, store, request, false)
}

func TestRateLimitBoundaryDoesNotUseForeignStoreScope(t *testing.T) {
	first, second := NewStore(), NewStore()
	request := boundaryRateRequest()
	request.Limit = 1
	err := first.InAuthTransaction(context.Background(), func(ctx context.Context) error {
		result, err := second.TakeRateLimit(ctx, request)
		if err != nil || !result.Allowed {
			return errors.New("independent store must admit the attempt")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	requireBoundaryAdmission(t, first, request, true)
	requireBoundaryAdmission(t, second, request, false)
}

func TestRateLimitBoundaryEmailQuotaStillRollsBack(t *testing.T) {
	store := NewStore()
	now := boundaryRateRequest().Now
	id := goauth.NewSubjectID()
	_, err := store.CreateLocalAccount(context.Background(), goauth.LocalAccountRecord{Account: goauth.Account{
		Subject: goauth.Subject{ID: id, Status: goauth.SubjectStatusActive, SecurityVersion: 1},
		PrimaryEmail: goauth.Identifier{
			ID: "email", SubjectID: id, Scheme: goauth.IdentifierSchemeEmail,
			DisplayValue: "old@example.test", NormalizedValue: "old@example.test",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	record := goauth.EmailChangeRecord{
		ID: "change", SubjectID: id, NewDisplayValue: "new@example.test", NewNormalizedValue: "new@example.test",
		Digest: boundaryRateRequest().Bucket, RateDigest: boundaryRateRequest().Bucket,
		MaxAttempts: 5, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	limits := goauth.EmailChallengeLimits{PerHour: 1, PerDay: 1}
	rollbackErr := errors.New("notification failed")
	err = store.InAuthTransaction(context.Background(), func(ctx context.Context) error {
		result, err := store.IssueEmailChange(ctx, record, limits)
		if err != nil || result.Status != goauth.EmailChangeIssued {
			return errors.New("transactional email issue failed")
		}
		return rollbackErr
	})
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("rollback = %v", err)
	}
	if _, err := store.GetPendingEmailChange(context.Background(), id, now); !errors.Is(err, goauth.ErrEmailChangeNotFound) {
		t.Fatalf("rolled-back email change remained: %v", err)
	}
	result, err := store.IssueEmailChange(context.Background(), record, limits)
	if err != nil || result.Status != goauth.EmailChangeIssued {
		t.Fatalf("email quota did not roll back: %v, %v", result, err)
	}
}
