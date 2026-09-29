package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserRejectsAmbiguousCredentialsBeforeHandler(t *testing.T) {
	for _, tc := range []struct{ name, cookie, authorization, action string }{
		{"duplicate access", "__Host-SSID=one; __Host-SSID=two", "", "me"},
		{"duplicate refresh", "__Host-UUIDR=one; __Host-UUIDR=two", "", "refresh"},
		{"Bearer and cookie", "__Host-SSID=one", "Bearer two", "me"},
		{"Bearer only", "", "Bearer two", "me"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := (host{secure: true}).browser(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }), tc.action)
			r := httptest.NewRequestWithContext(t.Context(), "POST", "/browser/"+tc.action, nil)
			r.Header.Set("X-Goauth-CSRF", "1")
			r.Header.Set("Cookie", tc.cookie)
			if tc.authorization != "" {
				r.Header.Set("Authorization", tc.authorization)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 || called {
				t.Fatal("ambiguous credential reached protected handler")
			}
		})
	}
}
