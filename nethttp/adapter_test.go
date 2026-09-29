//nolint:lll // Test fixtures keep request and response contracts visible together.
package nethttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/assurrussa/goauth"
	authhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/testkit"
)

func TestDefaultSessionVerificationRejectsRevocation(t *testing.T) {
	fixture, err := testkit.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := authhttp.New(fixture.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // This is a synthetic password in an in-memory test fixture.
	registered, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{Email: "http@example.test", Password: "Unique-Nethttp-Passphrase-1"})
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := authhttp.AuthContext(r.Context())
		if !ok || auth.SubjectID != registered.Account.Subject.ID {
			t.Error("missing auth context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	online := adapter.RequireRealm(goauth.RealmUser, authhttp.RealmMiddlewareOptions{AllowConfirmation: true})(next)
	offline := adapter.RequireRealm(goauth.RealmUser, authhttp.RealmMiddlewareOptions{AllowConfirmation: true, OfflineJWT: true})(next)
	check := func(handler http.Handler, want int) {
		t.Helper()
		request := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
		request.Header.Set("Authorization", "Bearer "+registered.Tokens.AccessToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("status %d want %d: %s", response.Code, want, response.Body)
		}
	}
	check(online, 204)
	if err := fixture.Runtime.Logout(t.Context(), registered.Account.Subject.ID, registered.Tokens.Session.ID); err != nil {
		t.Fatal(err)
	}
	check(online, 401)
	check(offline, 204)
}

func TestRealmAndConfirmationBoundaries(t *testing.T) {
	fixture, err := testkit.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := authhttp.New(fixture.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // This is a synthetic password in an in-memory test fixture.
	result, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{Email: "scope@example.test", Password: "Unique-Nethttp-Passphrase-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		realm goauth.Realm
		token string
		want  int
	}{{goauth.RealmUser, result.Tokens.AccessToken, 403}, {goauth.RealmAdmin, result.Tokens.AccessToken, 403}, {goauth.RealmUser, "", 401}} {
		request := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
		request.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		adapter.RequireRealm(test.realm, authhttp.RealmMiddlewareOptions{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthorized handler executed") })).ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("status %d want %d", response.Code, test.want)
		}
	}
}

func TestJSONAndErrors(t *testing.T) {
	fixture, err := testkit.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := authhttp.New(fixture.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{`, `{"email":"valid@example.test","password":"Unique-Nethttp-Passphrase-1"} {}`, strings.Repeat(" ", 1<<20) + `{}`} {
		request := httptest.NewRequestWithContext(t.Context(), "POST", "/register", strings.NewReader(body))
		response := httptest.NewRecorder()
		adapter.Register(response, request)
		if response.Code != 422 {
			t.Fatalf("malformed status %d", response.Code)
		}
	}
	response := httptest.NewRecorder()
	adapter.Register(response, httptest.NewRequestWithContext(t.Context(), "POST", "/register", strings.NewReader(`{"email":"json@example.test","password":"Unique-Nethttp-Passphrase-1","displayName":"HTTP"}`)))
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body)
	}
	var result struct {
		Account struct {
			SubjectID string `json:"subjectId"`
			Email     string `json:"email"`
		} `json:"account"`
		Tokens struct {
			AccessToken string `json:"accessToken"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Account.SubjectID == "" || result.Account.Email != "json@example.test" || result.Tokens.AccessToken == "" {
		t.Fatal("wire contract", err, response.Body)
	}
	for _, test := range []struct {
		err         error
		status      int
		code, retry string
	}{{errors.New("secret database details"), 500, "internal_error", ""}, {goauth.ErrOperationOutcomeUnknown, 503, "operation_outcome_unknown", ""}, {goauth.ErrAuthenticationRateLimited, 429, "authentication_rate_limited", "900"}, {goauth.ErrRefreshReplay, 401, "refresh_replay", ""}} {
		response = httptest.NewRecorder()
		authhttp.WriteError(response, test.err)
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) || response.Header().Get("Retry-After") != test.retry || strings.Contains(response.Body.String(), "secret database") {
			t.Fatal(response.Code, response.Body)
		}
	}
}

type resetSpy struct {
	authhttp.Runtime
	calls int
}

func (s *resetSpy) RequestPasswordReset(context.Context, string) error { s.calls++; return nil }

func TestMalformedResetRequestDoesNotInvokeRuntime(t *testing.T) {
	spy := &resetSpy{}
	adapter, err := authhttp.New(spy)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"email":"partial@example.test",`, `{"email":"trailing@example.test"} {}`} {
		response := httptest.NewRecorder()
		adapter.RequestPasswordReset(response, httptest.NewRequestWithContext(t.Context(), "POST", "/reset-request", strings.NewReader(body)))
		if response.Code != http.StatusAccepted {
			t.Fatalf("status %d", response.Code)
		}
		decoder := json.NewDecoder(response.Body)
		var accepted struct {
			Accepted bool `json:"accepted"`
		}
		if err := decoder.Decode(&accepted); err != nil || !accepted.Accepted {
			t.Fatalf("accepted response: %v", err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			t.Fatalf("expected single JSON response: %v", err)
		}
	}
	if spy.calls != 0 {
		t.Fatalf("malformed reset invoked runtime %d times", spy.calls)
	}
}
