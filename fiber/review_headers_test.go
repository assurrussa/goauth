package fiber_test

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
	goauthfiber "github.com/assurrussa/goauth/fiber"
)

type reviewHeaderRuntime struct{ goauthfiber.Runtime }

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
	adapter, err := goauthfiber.New(reviewHeaderRuntime{})
	require.NoError(t, err)
	app := gofiber.New()
	app.Post("/register", adapter.Register)
	app.Post("/login", adapter.Login)
	app.Post("/refresh", adapter.Refresh)
	for _, path := range []string{"/register", "/login", "/refresh"} {
		for _, body := range []string{"{}", "{"} {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(body))
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
	for _, tc := range []struct {
		name   string
		err    error
		status int
		retry  string
	}{
		{"limited", errors.Join(errors.New("wrapper"), reviewRetryError{}), http.StatusTooManyRequests, "18"},
		{"unknown", errors.Join(goauth.ErrOperationOutcomeUnknown, reviewRetryError{}), http.StatusServiceUnavailable, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := gofiber.New()
			app.Get("/", func(c gofiber.Ctx) error { return goauthfiber.WriteError(c, tc.err) })
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			response, err := app.Test(request)
			require.NoError(t, err)
			require.Equal(t, tc.status, response.StatusCode)
			require.Equal(t, tc.retry, response.Header.Get("Retry-After"))
			require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
			require.NoError(t, response.Body.Close())
		})
	}
}

type reducedLimitRetryError struct {
	retryAfter time.Duration
}

func (e reducedLimitRetryError) Error() string             { return "rate limit exceeded" }
func (e reducedLimitRetryError) Unwrap() error             { return goauth.ErrAuthenticationRateLimited }
func (e reducedLimitRetryError) RetryAfter() time.Duration { return e.retryAfter }

func TestReviewFiberRetryAfterReducedLimitWindowHeader(t *testing.T) {
	app := gofiber.New()
	app.Get("/", func(c gofiber.Ctx) error {
		return goauthfiber.WriteError(c, reducedLimitRetryError{retryAfter: 4 * time.Minute})
	})
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	response, err := app.Test(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusTooManyRequests, response.StatusCode)
	require.Equal(t, "240", response.Header.Get("Retry-After"))
	require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
	require.NoError(t, response.Body.Close())
}
