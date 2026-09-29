package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/assurrussa/goauth/testkit"
)

func TestBrowserCookiesCSRFAndAPISeparation(t *testing.T) {
	fixture, err := testkit.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newHandler(fixture.Runtime, true)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"email":"browser@example.test","password":"Unique-Browser-Passphrase-1"}`
	request := func(method, path, body, origin, csrf string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if csrf != "" {
			r.Header.Set("X-Goauth-CSRF", csrf)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, attack := range []struct{ origin, csrf string }{{"", ""}, {"https://evil.example", "1"}} {
		w := request("POST", "/browser/register", body, attack.origin, attack.csrf, nil)
		if w.Code != 403 {
			t.Fatal("CSRF accepted", w.Code)
		}
	}
	w := request("POST", "/browser/register", body, "", "1", nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "accessToken") || strings.Contains(w.Body.String(), "refreshToken") {
		t.Fatal("browser leaked tokens")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatal("missing cookies")
	}
	for _, cookie := range cookies {
		if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
			t.Fatal("unsafe cookie", cookie.Name)
		}
	}
	if got := request("POST", "/api/email-send", "{}", "", "", cookies).Code; got != 401 {
		t.Fatal("API accepted browser cookie", got)
	}
	if got := request("GET", "/browser/logout", "", "", "", cookies).Code; got != 405 {
		t.Fatal("mutating GET accepted", got)
	}
	if got := request("POST", "/browser/email-send", "{}", "", "1", cookies).Code; got != 202 {
		t.Fatal("browser confirmation", got)
	}
	if got := request("GET", "/browser/me", "", "", "", cookies).Code; got != 403 {
		t.Fatal("confirmation scope accepted", got)
	}
	if got := request("POST", "/browser/logout", "{}", "", "1", cookies).Code; got != 204 {
		t.Fatal("logout", got)
	}
	if got := request("POST", "/browser/email-send", "{}", "", "1", cookies).Code; got != 401 {
		t.Fatal("revoked cookie accepted", got)
	}
	w = request("POST", "/api/register", `{"email":"api@example.test","password":"Unique-API-Passphrase-1"}`, "", "", nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("API set cookies")
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil || value["tokens"] == nil {
		t.Fatal("API missing tokens", err)
	}
}
