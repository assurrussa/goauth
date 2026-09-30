package fiber_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gofiber "github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	goauthfiber "github.com/assurrussa/goauth/fiber"
)

type explicitAuthenticationRuntime struct {
	goauthfiber.Runtime
	sessionCalls, jwtCalls int
}

func (r *explicitAuthenticationRuntime) AuthenticateSession(context.Context, string) (goauth.AuthContext, error) {
	r.sessionCalls++
	return goauth.AuthContext{SubjectID: goauth.NewSubjectID(), SessionID: "session", Realm: goauth.RealmUser}, nil
}

func (r *explicitAuthenticationRuntime) VerifyJWT(context.Context, string) (goauth.AuthContext, error) {
	r.jwtCalls++
	return goauth.AuthContext{SubjectID: goauth.NewSubjectID(), SessionID: "session", Realm: goauth.RealmUser}, nil
}

func TestRealmUsesExplicitAuthenticationContract(t *testing.T) {
	for _, offline := range []bool{false, true} {
		runtime := &explicitAuthenticationRuntime{}
		adapter, err := goauthfiber.New(runtime)
		require.NoError(t, err)
		app := gofiber.New()
		app.Get("/", adapter.RequireRealm(goauth.RealmUser, goauthfiber.RealmMiddlewareOptions{OfflineJWT: offline}),
			func(c gofiber.Ctx) error { return c.SendStatus(http.StatusNoContent) })
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		request.Header.Set("Authorization", "Bearer access-token")
		response, err := app.Test(request)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusNoContent, response.StatusCode)
		if offline {
			require.Equal(t, 1, runtime.jwtCalls)
			require.Zero(t, runtime.sessionCalls)
		} else {
			require.Equal(t, 1, runtime.sessionCalls)
			require.Zero(t, runtime.jwtCalls)
		}
	}
}

func TestAuthHandlersRejectOversizedBodies(t *testing.T) {
	adapter, err := goauthfiber.New(reviewHeaderRuntime{})
	require.NoError(t, err)
	app := gofiber.New(gofiber.Config{BodyLimit: 2 << 20})
	handlers := []gofiber.Handler{
		adapter.Register, adapter.Login, adapter.Refresh, adapter.RequestPasswordReset,
		adapter.ResetPassword, adapter.SendEmailChallenge, adapter.VerifyEmailChallenge,
	}
	for index, handler := range handlers {
		path := "/" + string(rune('a'+index))
		app.Post(path, handler)
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(strings.Repeat(" ", (1<<20)+1)))
		request.Header.Set("Content-Type", "application/json")
		response, err := app.Test(request)
		require.NoError(t, err)
		require.Equal(t, http.StatusRequestEntityTooLarge, response.StatusCode)
		require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
		var payload goauthfiber.ErrorResponse
		require.NoError(t, json.NewDecoder(response.Body).Decode(&payload))
		require.NoError(t, response.Body.Close())
		require.Equal(t, "request_too_large", payload.Error.Code)
	}
	body := "{}" + strings.Repeat(" ", (1<<20)-2)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/a", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusCreated, response.StatusCode)
}
