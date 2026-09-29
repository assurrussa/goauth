package nethttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type reviewRetryError struct{}

func (reviewRetryError) Error() string             { return "limited" }
func (reviewRetryError) Unwrap() error             { return goauth.ErrAuthenticationRateLimited }
func (reviewRetryError) RetryAfter() time.Duration { return 17*time.Second + time.Millisecond }

func TestReviewRetryAfterUsesActualDeadline(t *testing.T) {
	recorder := httptest.NewRecorder()
	WriteError(recorder, errors.Join(errors.New("wrapper"), reviewRetryError{}))
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)
	require.Equal(t, "18", recorder.Header().Get("Retry-After"))
	require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))

	recorder = httptest.NewRecorder()
	WriteError(recorder, errors.Join(goauth.ErrOperationOutcomeUnknown, reviewRetryError{}))
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.Empty(t, recorder.Header().Get("Retry-After"))
}
