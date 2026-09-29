package fiber_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	basefiber "github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	goauthfiber "github.com/assurrussa/goauth/fiber"
)

func TestWriteErrorOutcomePrecedence(t *testing.T) {
	const outcomeCode = "operation_outcome_unknown"
	type errorCase struct {
		name        string
		err         error
		status      int
		code, retry string
	}
	tests := make([]errorCase, 0, 23)
	tests = append(tests, []errorCase{
		{"unknown", goauth.ErrOperationOutcomeUnknown, 503, outcomeCode, ""},
		{"wrapped_unknown", fmt.Errorf("secret database details: %w", goauth.ErrOperationOutcomeUnknown), 503, outcomeCode, ""},
		{"canceled", context.Canceled, 503, "authentication_unavailable", ""},
		{"deadline", context.DeadlineExceeded, 503, "authentication_unavailable", ""},
		{"hash_overload", goauth.ErrPasswordHashOverloaded, 503, "password_hash_overloaded", "1"},
		{"rate_limit", goauth.ErrAuthenticationRateLimited, 429, "authentication_rate_limited", "900"},
		{"internal", errors.New("secret database details"), 500, "internal_error", ""},
	}...)
	for _, cause := range []struct {
		name string
		err  error
	}{
		{"canceled", context.Canceled},
		{"deadline", context.DeadlineExceeded},
		{"hash_overload", goauth.ErrPasswordHashOverloaded},
		{"rate_limit", goauth.ErrAuthenticationRateLimited},
	} {
		for _, unknownFirst := range []bool{true, false} {
			joined := errors.Join(goauth.ErrOperationOutcomeUnknown, cause.err)
			if !unknownFirst {
				joined = errors.Join(cause.err, goauth.ErrOperationOutcomeUnknown)
			}
			tests = append(tests, errorCase{
				fmt.Sprintf("joined_%s_unknown_first_%t", cause.name, unknownFirst), joined, 503, outcomeCode, "",
			}, errorCase{
				fmt.Sprintf("wrapped_joined_%s_unknown_first_%t", cause.name, unknownFirst),
				fmt.Errorf("secret database details: %w", joined), 503, outcomeCode, "",
			})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := basefiber.New()
			app.Get("/", func(c basefiber.Ctx) error { return goauthfiber.WriteError(c, test.err) })
			response, err := app.Test(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, test.status, response.StatusCode)
			require.Equal(t, test.retry, response.Header.Get("Retry-After"))
			var payload goauthfiber.ErrorResponse
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			require.NoError(t, decoder.Decode(&payload))
			require.ErrorIs(t, decoder.Decode(new(any)), io.EOF)
			require.Equal(t, test.code, payload.Error.Code)
			require.NotEmpty(t, payload.Error.Message)
			require.NotContains(t, string(body), "secret database details")
		})
	}
}
