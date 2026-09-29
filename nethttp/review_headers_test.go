package nethttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	authhttp "github.com/assurrussa/goauth/nethttp"
)

type reviewRetryError struct{}

func (reviewRetryError) Error() string             { return "limited" }
func (reviewRetryError) Unwrap() error             { return goauth.ErrAuthenticationRateLimited }
func (reviewRetryError) RetryAfter() time.Duration { return 17*time.Second + time.Millisecond }

func TestReviewRetryAfterUsesActualDeadline(t *testing.T) {
	recorder := httptest.NewRecorder()
	authhttp.WriteError(recorder, errors.Join(errors.New("wrapper"), reviewRetryError{}))
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)
	require.Equal(t, "18", recorder.Header().Get("Retry-After"))
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))

	recorder = httptest.NewRecorder()
	authhttp.WriteError(recorder, errors.Join(goauth.ErrOperationOutcomeUnknown, reviewRetryError{}))
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.Empty(t, recorder.Header().Get("Retry-After"))
}

type reducedLimitRetryError struct {
	retryAfter time.Duration
}

func (e reducedLimitRetryError) Error() string             { return "rate limit exceeded" }
func (e reducedLimitRetryError) Unwrap() error             { return goauth.ErrAuthenticationRateLimited }
func (e reducedLimitRetryError) RetryAfter() time.Duration { return e.retryAfter }

func TestReviewRetryAfterReducedLimitWindowHeader(t *testing.T) {
	// 5 events at 12:00..12:04 with 1-hour window.
	// Limit reduced to 2.
	// Limiting event is 12:03. Deadline is 13:03.
	// At 12:59, remaining duration is 4 minutes = 240 seconds.
	recorder := httptest.NewRecorder()
	authhttp.WriteError(recorder, reducedLimitRetryError{retryAfter: 4 * time.Minute})
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)
	require.Equal(t, "240", recorder.Header().Get("Retry-After"))
}
