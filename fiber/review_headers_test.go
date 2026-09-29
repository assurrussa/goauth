package fiber

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gofiber "github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type reviewHeaderRuntime struct{ Runtime }

func (reviewHeaderRuntime) Register(context.Context, goauth.RegisterRequest) (goauth.RegisterResult, error) {
	return goauth.RegisterResult{}, nil
}

func (reviewHeaderRuntime) Login(context.Context, goauth.LoginRequest) (goauth.LoginResult, error) {
	return goauth.LoginResult{}, nil
}

func (reviewHeaderRuntime) Refresh(context.Context, string) (goauth.TokenPair, error) {
	return goauth.TokenPair{}, nil
}

func TestReviewTokenResponsesCannotBeCached(t *testing.T) {
	adapter, err := New(reviewHeaderRuntime{})
	require.NoError(t, err)
	app := gofiber.New()
	app.Post("/register", adapter.Register)
	app.Post("/login", adapter.Login)
	app.Post("/refresh", adapter.Refresh)
	for _, path := range []string{"/register", "/login", "/refresh"} {
		for _, body := range []string{"{}", "{"} {
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response, err := app.Test(request)
			require.NoError(t, err)
			require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
			require.NoError(t, response.Body.Close())
		}
	}
}

type reviewRetryError struct{}

func (reviewRetryError) Error() string             { return "limited" }
func (reviewRetryError) Unwrap() error             { return goauth.ErrAuthenticationRateLimited }
func (reviewRetryError) RetryAfter() time.Duration { return 17*time.Second + time.Millisecond }

func TestReviewRetryAfterUsesActualDeadline(t *testing.T) {
	seconds, ok := retryAfterSeconds(errors.Join(errors.New("wrapper"), reviewRetryError{}))
	require.True(t, ok)
	require.Equal(t, 18, seconds)
	_, ok = retryAfterSeconds(errors.Join(goauth.ErrOperationOutcomeUnknown, reviewRetryError{}))
	require.False(t, ok)
}
