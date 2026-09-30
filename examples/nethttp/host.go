package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/assurrussa/goauth"
	authhttp "github.com/assurrussa/goauth/nethttp"
)

// Browser cookies are host policy. API requests never pass through this bridge.
const refreshAction = "refresh"

type host struct{ secure bool }

func (h host) accessCookieName() string {
	if h.secure {
		return "__Host-SSID"
	}
	return "goauth_dev_SSID"
}

func (h host) refreshCookieName() string {
	if h.secure {
		return "__Host-UUIDR"
	}
	return "goauth_dev_UUIDR"
}

func (h host) cookie(w http.ResponseWriter, name, value string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if value == "" {
		maxAge = -1
	}
	//nolint:gosec // Secure is disabled only by explicitly configured localhost development.
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/",
		HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode,
		Expires: expires, MaxAge: maxAge,
	})
}

func (h host) clear(w http.ResponseWriter) {
	h.cookie(w, h.accessCookieName(), "", time.Unix(1, 0))
	h.cookie(w, h.refreshCookieName(), "", time.Unix(1, 0))
}

type responseBuffer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *responseBuffer) Header() http.Header { return b.header }
func (b *responseBuffer) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *responseBuffer) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(data)
}

func (h host) browser(next http.Handler, action string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// A non-simple custom header, plus CrossOriginProtection below, guards
		// anonymous login as well as authenticated mutations against CSRF.
		if r.Method != http.MethodGet && r.Header.Get("X-Goauth-CSRF") != "1" {
			http.Error(w, "CSRF header required", http.StatusForbidden)
			return
		}
		r = r.Clone(r.Context())
		// This browser assembly has one credential source. Never silently choose
		// between injected duplicate cookies or a Bearer header and a cookie.
		if len(r.Header.Values("Authorization")) != 0 {
			authhttp.WriteError(w, goauth.ErrInvalidToken)
			return
		}
		cookie, err := singleCookie(r, h.accessCookieName())
		if err != nil {
			authhttp.WriteError(w, goauth.ErrInvalidToken)
			return
		}
		if cookie != nil {
			r.Header.Set("Authorization", "Bearer "+cookie.Value)
		}
		refreshCookie, err := singleCookie(r, h.refreshCookieName())
		if err != nil {
			authhttp.WriteError(w, goauth.ErrInvalidToken)
			return
		}
		if action == refreshAction {
			cookie := refreshCookie
			if cookie == nil {
				authhttp.WriteError(w, goauth.ErrInvalidToken)
				return
			}
			body, _ := json.Marshal(map[string]string{"refreshToken": cookie.Value})
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		out := &responseBuffer{header: make(http.Header)}
		next.ServeHTTP(out, r)
		if out.status >= 200 && out.status < 300 {
			if err := h.success(w, out, action); err != nil {
				http.Error(w, "invalid auth response", http.StatusInternalServerError)
				return
			}
		}
		for key, values := range out.header {
			w.Header()[key] = values
		}
		w.Header().Set("Cache-Control", "no-store")
		if out.status == 0 {
			out.status = 200
		}
		w.WriteHeader(out.status)
		_, _ = w.Write(out.body.Bytes())
	})
}

func singleCookie(r *http.Request, name string) (*http.Cookie, error) {
	var selected *http.Cookie
	for _, cookie := range r.Cookies() {
		if cookie.Name != name {
			continue
		}
		if selected != nil {
			return nil, goauth.ErrInvalidToken
		}
		selected = cookie
	}
	return selected, nil
}

func (h host) success(w http.ResponseWriter, out *responseBuffer, action string) error {
	switch action {
	case "logout", "logout-all", "password", "email-confirm", "reset":
		h.clear(w)
	case "register", "login", refreshAction:
		return h.tokens(w, out)
	}
	return nil
}

func (h host) tokens(w http.ResponseWriter, out *responseBuffer) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(out.body.Bytes(), &value); err != nil {
		return err
	}
	raw := out.body.Bytes()
	if nested, ok := value["tokens"]; ok {
		raw = nested
	}
	var tokens struct {
		AccessToken      string    `json:"accessToken"`
		RefreshToken     string    `json:"refreshToken"`
		AccessExpiresAt  time.Time `json:"accessExpiresAt"`
		RefreshExpiresAt time.Time `json:"refreshExpiresAt"`
	}
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		return goauth.ErrInvalidToken
	}
	delete(value, "tokens")
	delete(value, "accessToken")
	delete(value, "refreshToken")
	expiry, err := json.Marshal(tokens.AccessExpiresAt)
	if err != nil {
		return err
	}
	value["accessExpiresAt"] = expiry
	out.body.Reset()
	if err := json.NewEncoder(&out.body).Encode(value); err != nil {
		return err
	}
	h.cookie(w, h.accessCookieName(), tokens.AccessToken, tokens.AccessExpiresAt)
	h.cookie(w, h.refreshCookieName(), tokens.RefreshToken, tokens.RefreshExpiresAt)
	return nil
}

func newHandler(runtime authhttp.Runtime, secure bool) (http.Handler, error) {
	adapter, err := authhttp.New(runtime)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	h := host{secure: secure}
	mux.HandleFunc("POST /browser/forget-session", h.forgetSession)
	routes := []struct {
		path                    string
		handler                 http.HandlerFunc
		protected, confirmation bool
	}{
		{"register", adapter.Register, false, false},
		{"login", adapter.Login, false, false},
		{refreshAction, adapter.Refresh, false, false},
		{"reset-request", adapter.RequestPasswordReset, false, false},
		{"reset", adapter.ResetPassword, false, false},
		{"email-send", adapter.SendEmailChallenge, true, true},
		{"email-verify", adapter.VerifyEmailChallenge, true, true},
		{"logout", adapter.Logout, true, true},
		{"logout-all", adapter.LogoutAll, true, false},
		{"password", adapter.ChangePassword, true, false},
		{"email-change", adapter.RequestEmailChange, true, false},
		{"email-confirm", adapter.ConfirmEmailChange, true, false},
	}
	for _, route := range routes {
		var handler http.Handler = route.handler
		if route.protected {
			options := authhttp.RealmMiddlewareOptions{AllowConfirmation: route.confirmation}
			handler = adapter.RequireRealm(goauth.RealmUser, options)(handler)
		}
		mux.Handle("POST /api/"+route.path, handler)
		mux.Handle("POST /browser/"+route.path, h.browser(handler, route.path))
	}
	me := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, _ := authhttp.AuthContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		value := map[string]string{"subjectId": auth.SubjectID.String(), "realm": string(auth.Realm)}
		if err := json.NewEncoder(w).Encode(value); err != nil {
			return
		}
	})
	protected := adapter.RequireRealm(goauth.RealmUser, authhttp.RealmMiddlewareOptions{})(me)
	mux.Handle("GET /api/me", protected)
	mux.Handle("GET /browser/me", h.browser(protected, "me"))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("GET /app.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write(script)
	})
	return http.NewCrossOriginProtection().Handler(mux), nil
}
