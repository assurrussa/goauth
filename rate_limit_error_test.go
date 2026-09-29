package goauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	gofiber "github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	goauthfiber "github.com/assurrussa/goauth/fiber"
	authhttp "github.com/assurrussa/goauth/nethttp"
)

func TestRateLimitTransactionErrorIsNotCredentialFailureOrRetryHint(t *testing.T) {
	err := fmt.Errorf("check admission: %w", goauth.ErrRateLimitTransactionUnsupported)
	require.ErrorIs(t, err, goauth.ErrRateLimitTransactionUnsupported)
	recorder := httptest.NewRecorder()
	authhttp.WriteError(recorder, err)
	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Contains(t, recorder.Body.String(), "internal_error")
	require.NotContains(t, recorder.Body.String(), goauth.ErrRateLimitTransactionUnsupported.Error())
	require.Empty(t, recorder.Header().Get("Retry-After"))

	app := gofiber.New()
	app.Get("/", func(c gofiber.Ctx) error { return goauthfiber.WriteError(c, err) })
	response, testErr := app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	require.NoError(t, testErr)
	require.Equal(t, http.StatusInternalServerError, response.StatusCode)
	require.Empty(t, response.Header.Get("Retry-After"))
	require.NoError(t, response.Body.Close())
}
