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
	"github.com/assurrussa/goauth/testkit"
)

const (
	invalidRealmCode      = "invalid_realm"
	unregisteredRealmCode = "realm_not_registered"
)

func TestWriteErrorOutcomePrecedence(t *testing.T) {
	const outcomeCode = "operation_outcome_unknown"
	type errorCase struct {
		name        string
		err         error
		status      int
		code, retry string
	}
	tests := make([]errorCase, 0, 29)
	tests = append(tests, []errorCase{
		{"unknown", goauth.ErrOperationOutcomeUnknown, 503, outcomeCode, ""},
		{"wrapped_unknown", fmt.Errorf("secret database details: %w", goauth.ErrOperationOutcomeUnknown), 503, outcomeCode, ""},
		{"canceled", context.Canceled, 503, "authentication_unavailable", ""},
		{"deadline", context.DeadlineExceeded, 503, "authentication_unavailable", ""},
		{"hash_overload", goauth.ErrPasswordHashOverloaded, 503, "password_hash_overloaded", "1"},
		{"rate_limit", goauth.ErrAuthenticationRateLimited, 429, "authentication_rate_limited", "900"},
		{"internal", errors.New("secret database details"), 500, "internal_error", ""},
		{invalidRealmCode, goauth.ErrInvalidRealm, 400, invalidRealmCode, ""},
		{"wrapped_invalid_realm", fmt.Errorf("secret database details: %w", goauth.ErrInvalidRealm), 400, invalidRealmCode, ""},
		{"unregistered_realm", goauth.ErrRealmNotRegistered, 400, unregisteredRealmCode, ""},
		{
			"wrapped_unregistered_realm", fmt.Errorf("secret database details: %w", goauth.ErrRealmNotRegistered),
			400, unregisteredRealmCode, "",
		},
		{"invalid_credentials", goauth.ErrInvalidCredentials, 401, "invalid_credentials", ""},
		{"membership_denied", goauth.ErrMembershipDenied, 403, "membership_denied", ""},
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

func TestLoginRealmResponses(t *testing.T) {
	const email = "login.realm.fiber@example.test"
	password := strings.Join([]string{"Unique", "Realm", "Fiber", "Passphrase", "1"}, "-")
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	registered, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{Email: email, Password: password})
	require.NoError(t, err)
	adapter, err := goauthfiber.New(fixture.Runtime)
	require.NoError(t, err)
	app := basefiber.New()
	app.Post("/login", adapter.Login)
	for _, test := range []struct {
		name, realm string
		status      int
		code        string
	}{
		{"uppercase", "USER", 400, invalidRealmCode},
		{"unregistered", "staff", 400, unregisteredRealmCode},
		{"invalid_characters", "bad realm", 400, invalidRealmCode},
		{"too_long", strings.Repeat("x", 33), 400, invalidRealmCode},
		{"default", "", 200, ""},
		{"user", "user", 200, ""},
		{"unverified_admin", "admin", 403, "email_verification_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := map[string]string{"identifier": email, "password": password}
			if test.realm != "" {
				input["realm"] = test.realm
			}
			body, err := json.Marshal(input)
			require.NoError(t, err)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			response, err := app.Test(request)
			require.NoError(t, err)
			data, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, test.status, response.StatusCode)
			require.Empty(t, response.Header.Get("Retry-After"))
			if test.status == http.StatusOK {
				var payload struct {
					Tokens struct {
						AccessToken string `json:"accessToken"`
					} `json:"tokens"`
				}
				require.NoError(t, json.Unmarshal(data, &payload))
				auth, err := fixture.Runtime.AuthenticateSession(t.Context(), payload.Tokens.AccessToken)
				require.NoError(t, err)
				require.Equal(t, goauth.RealmUser, auth.Realm)
			} else {
				var payload goauthfiber.ErrorResponse
				require.NoError(t, json.Unmarshal(data, &payload))
				require.Equal(t, test.code, payload.Error.Code)
				require.NotEmpty(t, payload.Error.Message)
				require.NotContains(t, string(data), test.realm)
			}
			account, err := fixture.Store.GetAccount(t.Context(), registered.Account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, registered.Account, account)
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
			require.NoError(t, err)
			require.Empty(t, fixture.Events.Events())
		})
	}
}
