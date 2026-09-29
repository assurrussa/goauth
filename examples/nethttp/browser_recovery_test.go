package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	authhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/testkit"
)

// Any unexpected call to the nil embedded Runtime would panic: recovery must
// work without consulting an authentication backend or validating stale cookies.
type forgetOnlyRuntime struct{ authhttp.Runtime }

func TestBrowserForgetSessionCSRFAndCookieScope(t *testing.T) {
	t.Parallel()
	for _, secure := range []bool{true, false} {
		h := host{secure: secure}
		handler, err := newHandler(&forgetOnlyRuntime{}, secure)
		require.NoError(t, err)
		for _, tc := range []struct {
			method, path, csrf, origin string
			status                     int
		}{
			{http.MethodPost, "/browser/forget-session", "1", "https://example.com", http.StatusOK},
			{http.MethodPost, "/browser/forget-session", "", "https://example.com", http.StatusForbidden},
			{http.MethodPost, "/browser/forget-session", "1", "https://hostile.example", http.StatusForbidden},
			{http.MethodGet, "/browser/forget-session", "1", "https://example.com", http.StatusMethodNotAllowed},
			{http.MethodPost, "/api/forget-session", "1", "https://example.com", http.StatusNotFound},
		} {
			request := httptest.NewRequestWithContext(t.Context(), tc.method, "https://example.com"+tc.path, nil)
			request.Header.Set("X-Goauth-CSRF", tc.csrf)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Cookie", h.accessCookieName()+"=expired; "+h.accessCookieName()+"=duplicate")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			require.Equal(t, tc.status, response.Code)
			result := response.Result()
			cookies := result.Cookies()
			require.NoError(t, result.Body.Close())
			if tc.status != http.StatusOK {
				require.Empty(t, cookies)
				continue
			}
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.Len(t, cookies, 2)
			require.ElementsMatch(t, []string{h.accessCookieName(), h.refreshCookieName()}, []string{cookies[0].Name, cookies[1].Name})
			for _, cookie := range cookies {
				require.Empty(t, cookie.Value)
				require.Negative(t, cookie.MaxAge)
				require.Equal(t, "/", cookie.Path)
				require.Empty(t, cookie.Domain)
				require.True(t, cookie.HttpOnly)
				require.Equal(t, secure, cookie.Secure)
				require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			}
			var payload map[string]bool
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
			require.Equal(t, map[string]bool{"browserCredentialsCleared": true, "serverSessionsRevoked": false}, payload)
		}
	}
}

func TestBrowserForgetDoesNotRevokeCanonicalSession(t *testing.T) {
	t.Parallel()
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	password := strings.Join([]string{"Browser", "Forget", "Passphrase", "42"}, "-")
	registered, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{
		Email: "browser.forget@example.test", Password: password,
	})
	require.NoError(t, err)
	handler, err := newHandler(fixture.Runtime, true)
	require.NoError(t, err)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/browser/forget-session", nil)
	request.Header.Set("X-Goauth-CSRF", "1")
	request.AddCookie(&http.Cookie{Name: "__Host-SSID", Value: registered.Tokens.AccessToken})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	_, err = fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
	require.NoError(t, err, "local cookie deletion must not be advertised as server revocation")
	_, err = fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
	require.NoError(t, err, "the independent refresh credential was neither consumed nor revoked")
}
