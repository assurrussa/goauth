package goauth_test

import (
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
	authfiber "github.com/assurrussa/goauth/fiber"
	authhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/testkit"
)

func TestPasswordVerifierOutageHTTPHandlers(t *testing.T) {
	t.Parallel()
	fault := errors.New("synthetic private verifier connection details")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"raw", goauth.ErrPasswordVerificationUnavailable},
		{"wrapped marker", fmt.Errorf("%w: %w", goauth.ErrPasswordVerificationUnavailable, fault)},
		{"joined marker", errors.Join(fault, goauth.ErrPasswordVerificationUnavailable)},
	} {
		for _, operation := range []string{
			"nethttp login", "fiber login", customHasherCurrentPasswordOperation, customHasherReplacementPasswordOperation,
		} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				t.Parallel()
				hasher := &legacyBcryptHasher{}
				fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.PasswordHasher = hasher })
				require.NoError(t, err)
				const email = "http.verifier.outage@example.test"
				registered := registerAccount(t, fixture, email)
				const replacement = "Replacement-Legacy-Passphrase-2"
				hasher.failure = tc.err
				if operation == customHasherReplacementPasswordOperation {
					hasher.failurePassword = replacement
				}
				var input any = struct {
					Identifier string `json:"identifier"`
					Password   string `json:"password"`
				}{Identifier: email, Password: testPassword}
				if operation == customHasherCurrentPasswordOperation || operation == customHasherReplacementPasswordOperation {
					input = map[string]string{"currentPassword": testPassword, "newPassword": replacement}
				}
				body, err := json.Marshal(input)
				require.NoError(t, err)
				request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(string(body)))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+registered.Tokens.AccessToken)
				var response *http.Response
				if operation == "fiber login" {
					adapter, err := authfiber.New(fixture.Runtime)
					require.NoError(t, err)
					app := basefiber.New()
					app.Post("/", adapter.Login)
					response, err = app.Test(request)
					require.NoError(t, err)
				} else {
					adapter, err := authhttp.New(fixture.Runtime)
					require.NoError(t, err)
					handler := http.Handler(http.HandlerFunc(adapter.Login))
					if operation == customHasherCurrentPasswordOperation || operation == customHasherReplacementPasswordOperation {
						handler = adapter.RequireRealm(goauth.RealmUser, authhttp.RealmMiddlewareOptions{
							AllowConfirmation: true,
						})(http.HandlerFunc(adapter.ChangePassword))
					}
					recorder := httptest.NewRecorder()
					handler.ServeHTTP(recorder, request)
					response = recorder.Result()
				}
				payload, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				require.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
				require.Empty(t, response.Header.Get("Retry-After"))
				var wire authhttp.ErrorResponse
				require.NoError(t, json.Unmarshal(payload, &wire))
				require.Equal(t, "authentication_unavailable", wire.Error.Code)
				require.Equal(t, "authentication temporarily unavailable", wire.Error.Message)
				require.NotContains(t, string(payload), fault.Error())
				account, err := fixture.Runtime.GetAccount(t.Context(), registered.Account.Subject.ID)
				require.NoError(t, err)
				require.Equal(t, registered.Account, account)
				require.Empty(t, fixture.Events.Events())
				hasher.failure = nil
				_, err = fixture.Runtime.VerifyCredential(t.Context(), loginRequest(email, testPassword, goauth.RealmUser).Credential)
				require.NoError(t, err)
				_, err = fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
				require.NoError(t, err)
			})
		}
	}
}
