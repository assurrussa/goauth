package fiber_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestJSONRegisterAndRealmMiddleware(t *testing.T) {
	t.Parallel()
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	adapter, err := goauthfiber.New(fixture.Runtime)
	require.NoError(t, err)
	app := basefiber.New()
	app.Post("/register", adapter.Register)
	app.Get(
		"/confirmation",
		adapter.RequireRealm(goauth.RealmUser, goauthfiber.RealmMiddlewareOptions{
			Introspect:        true,
			AllowConfirmation: true,
		}),
		func(c basefiber.Ctx) error {
			auth, ok := goauthfiber.AuthContext(c)
			if !ok {
				return c.SendStatus(basefiber.StatusInternalServerError)
			}
			return c.JSON(basefiber.Map{"subjectId": auth.SubjectID.String(), "scope": auth.Scope})
		},
	)
	app.Get(
		"/authenticated",
		adapter.RequireRealm(goauth.RealmUser, goauthfiber.RealmMiddlewareOptions{Introspect: true}),
		func(c basefiber.Ctx) error { return c.SendStatus(basefiber.StatusOK) },
	)

	registerBody := `{"email":"fiber.user@example.test","password":"Unique-Fiber-Passphrase-1","displayName":"Fiber User"}`
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(registerBody))
	request.Header.Set(basefiber.HeaderContentType, basefiber.MIMEApplicationJSON)
	response, err := app.Test(request)
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()
	require.Equal(t, basefiber.StatusCreated, response.StatusCode)
	var registered map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&registered))
	tokens, ok := registered["tokens"].(map[string]any)
	require.True(t, ok)
	accessToken, ok := tokens["accessToken"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)
	require.Equal(t, string(goauth.SessionScopeConfirmation), tokens["scope"])

	confirmationRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/confirmation", nil)
	confirmationRequest.Header.Set(basefiber.HeaderAuthorization, "Bearer "+accessToken)
	confirmationResponse, err := app.Test(confirmationRequest)
	require.NoError(t, err)
	defer func() { require.NoError(t, confirmationResponse.Body.Close()) }()
	require.Equal(t, basefiber.StatusOK, confirmationResponse.StatusCode)

	authenticatedRequest := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authenticated", nil)
	authenticatedRequest.Header.Set(basefiber.HeaderAuthorization, "Bearer "+accessToken)
	authenticatedResponse, err := app.Test(authenticatedRequest)
	require.NoError(t, err)
	defer func() { require.NoError(t, authenticatedResponse.Body.Close()) }()
	require.Equal(t, basefiber.StatusForbidden, authenticatedResponse.StatusCode)
}

func TestPasswordResetRequestIsEnumerationSafeAtHTTPBoundary(t *testing.T) {
	t.Parallel()
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	password := strings.Join([]string{"Unique", "Reset", "Passphrase", "1"}, "-")
	_, err = fixture.Runtime.Register(context.Background(), goauth.RegisterRequest{
		Email:    "known@example.test",
		Password: password,
	})
	require.NoError(t, err)
	adapter, err := goauthfiber.New(fixture.Runtime)
	require.NoError(t, err)
	app := basefiber.New()
	app.Post("/password-reset", adapter.RequestPasswordReset)

	known := resetRequest(t, app, "known@example.test")
	defer func() { require.NoError(t, known.Body.Close()) }()
	unknown := resetRequest(t, app, "missing@example.test")
	defer func() { require.NoError(t, unknown.Body.Close()) }()
	require.Equal(t, basefiber.StatusAccepted, known.StatusCode)
	require.Equal(t, basefiber.StatusAccepted, unknown.StatusCode)
	knownBody, err := io.ReadAll(known.Body)
	require.NoError(t, err)
	unknownBody, err := io.ReadAll(unknown.Body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(knownBody, unknownBody))
}

func TestTypedErrorMappingRedactsInternalDetails(t *testing.T) {
	t.Parallel()
	app := basefiber.New()
	app.Get("/", func(c basefiber.Ctx) error {
		return goauthfiber.WriteError(c, errors.New("database password is super-secret"))
	})
	response, err := app.Test(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()
	require.Equal(t, basefiber.StatusInternalServerError, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NotContains(t, string(body), "super-secret")
	require.Contains(t, string(body), "internal_error")
}

func resetRequest(t *testing.T, app *basefiber.App, email string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]string{"email": email})
	require.NoError(t, err)
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/password-reset", bytes.NewReader(body))
	request.Header.Set(basefiber.HeaderContentType, basefiber.MIMEApplicationJSON)
	response, err := app.Test(request)
	require.NoError(t, err)

	return response
}
