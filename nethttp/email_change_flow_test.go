package nethttp_test

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

func TestEmailChangeHTTPVerifiedSessionLifecycle(t *testing.T) {
	t.Parallel()
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	password := strings.Join([]string{"Email", "Change", "Lifecycle", "Secret", "42"}, "-")
	const oldEmail = "email.http.old@example.test"
	const newEmail = "email.http.new@example.test"
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: oldEmail, Password: password,
	})
	require.NoError(t, err)
	login, err := fixture.Runtime.Login(t.Context(), goauth.LoginRequest{
		Credential: goauth.Credential{Identifier: goauth.IdentifierInput{Value: oldEmail}, Password: password},
		Realm:      goauth.RealmUser,
	})
	require.NoError(t, err)
	adapter, err := authhttp.New(fixture.Runtime)
	require.NoError(t, err)
	call := func(handler http.HandlerFunc, values map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(values)
		require.NoError(t, err)
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/email-change", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+login.Tokens.AccessToken)
		response := httptest.NewRecorder()
		adapter.RequireRealm(goauth.RealmUser, authhttp.RealmMiddlewareOptions{})(handler).ServeHTTP(response, request)
		return response
	}
	for _, current := range []string{"", "incorrect"} {
		response := call(adapter.RequestEmailChange, map[string]string{fieldEmail: newEmail, fieldCurrentPassword: current})
		require.Equal(t, http.StatusUnprocessableEntity, response.Code)
		var outcome authhttp.ErrorResponse
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &outcome))
		require.Equal(t, "current_password_invalid", outcome.Error.Code)
		require.Empty(t, fixture.Events.Events())
	}
	response := call(adapter.RequestEmailChange, map[string]string{
		fieldEmail: newEmail, fieldCurrentPassword: password, "subjectId": goauth.NewSubjectID().String(),
	})
	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	require.NotContains(t, response.Body.String(), password)
	pending, err := fixture.Runtime.PendingEmailChange(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, newEmail, pending.NewDisplayValue)
	events := fixture.Events.Events()
	require.Len(t, events, 1)
	require.Equal(t, "email_change", events[0].Type)
	notice, err := fixture.Runtime.DecryptNotificationEvent(events[0])
	require.NoError(t, err)
	require.Equal(t, newEmail, notice.To)
	require.Len(t, notice.Data["code"], 6)
	response = call(adapter.ConfirmEmailChange, map[string]string{"code": notice.Data["code"]})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	changed, err := fixture.Runtime.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, newEmail, changed.PrimaryEmail.NormalizedValue)
	_, err = fixture.Runtime.AuthenticateSession(t.Context(), login.Tokens.AccessToken)
	require.Error(t, err, "email confirmation must revoke the original session")
	events = fixture.Events.Events()
	require.Len(t, events, 2)
	require.Equal(t, "email_changed", events[1].Type)
	previousNotice, err := fixture.Runtime.DecryptNotificationEvent(events[1])
	require.NoError(t, err)
	require.Equal(t, oldEmail, previousNotice.To)
	require.Empty(t, previousNotice.Data)
}
