package testkit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	testChallengeIdentifier = "identifier"
	testChallengeKey        = "key"
	testChallengeRateKey    = "rate-key"
)

func TestEmailChallengeRateLimitIsAtomicAndBoundaryAware(t *testing.T) {
	t.Parallel()
	store := testkit.NewStore()
	subjectID := goauth.NewSubjectID()
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	limits := goauth.EmailChallengeLimits{PerHour: 5, PerDay: 10}
	var issued atomic.Int64
	var limited atomic.Int64
	var unexpected atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range 6 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{
				ID:           time.Duration(index).String(),
				SubjectID:    subjectID,
				IdentifierID: testChallengeIdentifier,
				Purpose:      goauth.EmailChallengePurposeVerification,
				Digest:       goauth.SecretDigest{KeyID: testChallengeKey, Digest: make([]byte, 32)},
				RateDigest:   goauth.SecretDigest{KeyID: testChallengeRateKey, Digest: make([]byte, 32)},
				MaxAttempts:  5,
				CreatedAt:    base,
				ExpiresAt:    base.Add(time.Hour),
			}, limits)
			if err != nil {
				unexpected.Add(1)
				return
			}
			switch result.Status {
			case goauth.EmailChallengeIssued:
				issued.Add(1)
			case goauth.EmailChallengeHourlyLimit:
				limited.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	require.EqualValues(t, 5, issued.Load())
	require.EqualValues(t, 1, limited.Load())
	require.Zero(t, unexpected.Load())

	boundary, err := store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{
		ID:           "boundary",
		SubjectID:    subjectID,
		IdentifierID: testChallengeIdentifier,
		Purpose:      goauth.EmailChallengePurposeVerification,
		Digest:       goauth.SecretDigest{KeyID: testChallengeKey, Digest: make([]byte, 32)},
		RateDigest:   goauth.SecretDigest{KeyID: testChallengeRateKey, Digest: make([]byte, 32)},
		MaxAttempts:  5,
		CreatedAt:    base.Add(time.Hour),
		ExpiresAt:    base.Add(2 * time.Hour),
	}, limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChallengeHourlyLimit, boundary.Status, "the rolling window includes the exact cutoff")

	afterBoundary, err := store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{
		ID:           "after-boundary",
		SubjectID:    subjectID,
		IdentifierID: testChallengeIdentifier,
		Purpose:      goauth.EmailChallengePurposeVerification,
		Digest:       goauth.SecretDigest{KeyID: testChallengeKey, Digest: make([]byte, 32)},
		RateDigest:   goauth.SecretDigest{KeyID: testChallengeRateKey, Digest: make([]byte, 32)},
		MaxAttempts:  5,
		CreatedAt:    base.Add(time.Hour + time.Microsecond),
		ExpiresAt:    base.Add(2 * time.Hour),
	}, limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChallengeIssued, afterBoundary.Status)
}
