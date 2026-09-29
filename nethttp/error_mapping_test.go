package nethttp_test

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
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	authhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/testkit"
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
			response := httptest.NewRecorder()
			authhttp.WriteError(response, test.err)
			body := response.Body.Bytes()
			require.Equal(t, test.status, response.Code)
			require.Equal(t, test.retry, response.Header().Get("Retry-After"))
			var payload authhttp.ErrorResponse
			decoder := json.NewDecoder(strings.NewReader(string(body)))
			require.NoError(t, decoder.Decode(&payload))
			require.ErrorIs(t, decoder.Decode(new(any)), io.EOF)
			require.Equal(t, test.code, payload.Error.Code)
			require.NotEmpty(t, payload.Error.Message)
			require.NotContains(t, string(body), "secret database details")
		})
	}
}

func TestWriteErrorAccountOutcomes(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{goauth.ErrCurrentPasswordInvalid, 422, "current_password_invalid"},
		{goauth.ErrPasswordUnchanged, 422, "password_unchanged"},
		{goauth.ErrPasswordChangeConflict, 409, "password_change_conflict"},
		{goauth.ErrEmailChangeSameValue, 422, "email_change_same_value"},
		{goauth.ErrEmailChangeNotFound, 404, "email_change_not_found"},
	} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_wrapped_%t", test.code, wrapped), func(t *testing.T) {
				err := test.err
				if wrapped {
					err = fmt.Errorf("secret database details: %w", err)
				}
				response := httptest.NewRecorder()
				authhttp.WriteError(response, err)
				require.Equal(t, test.status, response.Code)
				require.Empty(t, response.Header().Get("Retry-After"))
				var payload authhttp.ErrorResponse
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
				require.Equal(t, test.code, payload.Error.Code)
				require.NotEmpty(t, payload.Error.Message)
				require.NotContains(t, response.Body.String(), "secret database details")
			})
		}
	}
}

func TestAccountEndpointDenialsPreserveCanonicalState(t *testing.T) {
	const email = "account.http@example.test"
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	password := strings.Join([]string{"Unique", "HTTP", "Account", "Passphrase", "1"}, "-")
	registered, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{
		Email: email, Password: password,
	})
	require.NoError(t, err)
	adapter, err := authhttp.New(fixture.Runtime)
	require.NoError(t, err)
	before, err := fixture.Store.GetAccount(t.Context(), registered.Account.Subject.ID)
	require.NoError(t, err)
	eventsBefore := fixture.Events.Events()
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		body    map[string]string
		status  int
		code    string
	}{
		{
			"wrong_password", adapter.ChangePassword,
			map[string]string{"currentPassword": "wrong-password", "newPassword": "Replacement-HTTP-Passphrase-2"},
			422, "current_password_invalid",
		},
		{
			"unchanged_password", adapter.ChangePassword,
			map[string]string{"currentPassword": password, "newPassword": password},
			422, "password_unchanged",
		},
		{
			"unchanged_email", adapter.RequestEmailChange,
			map[string]string{"email": email},
			422, "email_change_same_value",
		},
		{
			"missing_pending_email", adapter.ConfirmEmailChange,
			map[string]string{"code": "123456"},
			404, "email_change_not_found",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.body)
			require.NoError(t, err)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/account", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+registered.Tokens.AccessToken)
			response := httptest.NewRecorder()
			handler := adapter.RequireRealm(goauth.RealmUser, authhttp.RealmMiddlewareOptions{AllowConfirmation: true})(test.handler)
			handler.ServeHTTP(response, request)
			var payload authhttp.ErrorResponse
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
			// Continue to state checks even when the response mapping is wrong.
			assertStatus := response.Code == test.status && payload.Error.Code == test.code
			if !assertStatus {
				t.Errorf("response %d %q; want %d %q", response.Code, payload.Error.Code, test.status, test.code)
			}
			require.Empty(t, response.Header().Get("Retry-After"))
			after, err := fixture.Store.GetAccount(t.Context(), registered.Account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Equal(t, eventsBefore, fixture.Events.Events())
			_, err = fixture.Runtime.VerifyCredential(t.Context(), goauth.Credential{
				Identifier: goauth.IdentifierInput{Value: email}, Password: password,
			})
			require.NoError(t, err)
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
			require.NoError(t, err)
			_, err = fixture.Store.GetPendingEmailChange(t.Context(), registered.Account.Subject.ID, time.Now())
			require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
		})
	}
}
