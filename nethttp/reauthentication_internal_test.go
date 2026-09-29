package nethttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/assurrussa/goauth"
)

const validEmailChangeBody = `{"email":"new@example.test","currentPassword":"secret"}`

type passwordEmailChangeStub struct {
	Runtime
	request goauth.PasswordEmailChangeRequest
	calls   int
	err     error
}

func (s *passwordEmailChangeStub) RequestEmailChangeWithPassword(
	_ context.Context,
	request goauth.PasswordEmailChangeRequest,
) error {
	s.calls++
	s.request = request
	return s.err
}

// An old host Runtime exposes the trusted operation but not the new capability.
// The HTTP adapter must never fall back to this method.
type trustedEmailChangeStub struct {
	Runtime
	calls int
}

func (s *trustedEmailChangeStub) RequestEmailChange(context.Context, goauth.SubjectID, string) error {
	s.calls++
	return nil
}

func emailChangeRequest(body string, scope goauth.SessionScope) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/email-change", strings.NewReader(body))
	auth := goauth.AuthContext{
		SubjectID: goauth.NewSubjectID(), SessionID: "checked-session", Realm: goauth.RealmUser, Scope: scope,
	}
	return r.WithContext(context.WithValue(r.Context(), authContextKey{}, auth))
}

func TestEmailChangeHandlerBindsPasswordToAuthenticatedSubject(t *testing.T) {
	t.Parallel()
	stub := &passwordEmailChangeStub{}
	adapter, err := New(stub)
	if err != nil {
		t.Fatal(err)
	}
	r := emailChangeRequest(
		`{"email":"new@example.test","currentPassword":" exact password ","subjectId":"attacker-selected"}`,
		goauth.SessionScopeAuthenticated,
	)
	w := httptest.NewRecorder()
	adapter.RequestEmailChange(w, r)
	auth, _ := AuthContext(r.Context())
	if w.Code != http.StatusAccepted || stub.calls != 1 || stub.request.SubjectID != auth.SubjectID ||
		stub.request.CurrentPassword != " exact password " || stub.request.NewEmail != "new@example.test" {
		t.Fatalf("reauthentication was not bound to the checked subject: status=%d calls=%d", w.Code, stub.calls)
	}
	if w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "exact password") {
		t.Fatal("credential response safety violated")
	}
}

func TestEmailChangeHandlerDeniesMissingProofOrConfirmationScope(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		body   string
		scope  goauth.SessionScope
		status int
	}{
		{"missing password", `{"email":"new@example.test"}`, goauth.SessionScopeAuthenticated, http.StatusUnprocessableEntity},
		{"confirmation scope", validEmailChangeBody, goauth.SessionScopeConfirmation, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := &passwordEmailChangeStub{}
			adapter, err := New(stub)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			adapter.RequestEmailChange(w, emailChangeRequest(tc.body, tc.scope))
			if w.Code != tc.status || stub.calls != 0 {
				t.Fatalf("unexpected status=%d calls=%d", w.Code, stub.calls)
			}
		})
	}
}

func TestEmailChangeHandlerNeverFallsBackToTrustedOperation(t *testing.T) {
	t.Parallel()
	stub := &trustedEmailChangeStub{}
	adapter, err := New(stub)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	adapter.RequestEmailChange(w, emailChangeRequest(validEmailChangeBody, goauth.SessionScopeAuthenticated))
	if w.Code != http.StatusServiceUnavailable || stub.calls != 0 {
		t.Fatalf("unsafe fallback: status=%d trusted calls=%d", w.Code, stub.calls)
	}
}

func TestEmailChangeHandlerPreservesPasswordFailureMapping(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"mismatch", goauth.ErrCurrentPasswordInvalid, http.StatusUnprocessableEntity},
		{"overload", goauth.ErrPasswordHashOverloaded, http.StatusServiceUnavailable},
		{"unavailable", goauth.ErrPasswordVerificationUnavailable, http.StatusServiceUnavailable},
		{"limit", goauth.ErrAuthenticationRateLimited, http.StatusTooManyRequests},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := &passwordEmailChangeStub{err: tc.err}
			adapter, err := New(stub)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			adapter.RequestEmailChange(w, emailChangeRequest(validEmailChangeBody, goauth.SessionScopeAuthenticated))
			if w.Code != tc.status || stub.calls != 1 {
				t.Fatalf("unexpected status=%d calls=%d", w.Code, stub.calls)
			}
		})
	}
}
