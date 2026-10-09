//nolint:testpackage // Exercises the signed canonical-identifier projection boundary.
package provider

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestSessionCanonicalIdentifiersSignedAndCopied(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	want := oidc.CanonicalIdentifiers{Version: 1, Login: "Main.Admin", EmailAlias: "admin@example.test"}
	h.admission.Projection.Identifiers = &want
	h.admission.Projection.Profile["login"] = "untrusted-display"
	h.admission.Projection.Profile["email_alias"] = "untrusted@example.test"
	h.admission.Projection.Profile["authhub_identifiers"] = `{"version":1,"login":"injected"}`
	response := h.issue(t)
	ctx := context.Background()
	key, err := h.keys.Active(ctx)
	require.NoError(t, err)
	claims := &sessionTokenClaims{}
	token, err := jwt.ParseWithClaims(response.IDToken, claims, func(*jwt.Token) (any, error) {
		return key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(h.service.base.issuer),
		jwt.WithAudience(h.admission.Client.ID), jwt.WithTimeFunc(h.service.now))
	require.NoError(t, err)
	require.True(t, token.Valid)
	require.Equal(t, &want, claims.Identifiers)
	standard := h.service.base.buildUserInfo(h.admission.Account, []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail})
	require.Equal(t, standard.Email, claims.Email)
	require.Equal(t, standard.EmailVerified, claims.EmailVerified)
	access, err := h.service.parseSessionAccessToken(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Nil(t, access.Identifiers, "matching identifiers are not access-token authorization")
	info, err := h.service.UserInfo(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Equal(t, &want, info.Identifiers)
	require.NotSame(t, &want, info.Identifiers)
	info.Identifiers.Login = "changed-output"
	require.Equal(t, "Main.Admin", want.Login)
	want.Login = "Current.Admin"
	require.Equal(t, "Main.Admin", claims.Identifiers.Login)
	info, err = h.service.UserInfo(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Equal(t, "Current.Admin", info.Identifiers.Login)
	refreshed, err := h.service.ExchangeToken(ctx, h.refreshRequest(response.RefreshToken))
	require.NoError(t, err)
	refreshedClaims := &sessionTokenClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(refreshed.IDToken, refreshedClaims)
	require.NoError(t, err)
	require.Equal(t, "Current.Admin", refreshedClaims.Identifiers.Login)
	require.Equal(t, claims.Subject, refreshedClaims.Subject)
	require.Contains(t, h.service.Discovery(ctx).ClaimsSupported, "authhub_identifiers")
}

func TestSessionCanonicalIdentifiersOptionalAndProfileScoped(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Projection.Profile["login"] = "metadata-login"
	h.admission.Projection.Profile["email_alias"] = "metadata@example.test"
	response := h.issue(t)
	claims := &sessionTokenClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(response.IDToken, claims)
	require.NoError(t, err)
	require.Nil(t, claims.Identifiers)
	info, err := h.service.UserInfo(context.Background(), response.AccessToken)
	require.NoError(t, err)
	require.Nil(t, info.Identifiers)
	encoded, err := json.Marshal(info)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), `"authhub_identifiers"`)
	h.admission.Projection.Identifiers = &oidc.CanonicalIdentifiers{Version: 1, Login: "Canonical"}
	info = h.service.userInfo(h.admission, []string{oidc.ScopeOpenID})
	require.Nil(t, info.Identifiers)
	withoutProfile, _, _, err := h.service.prepareTokens(context.Background(), h.admission,
		h.admission.Binding, []string{oidc.ScopeOpenID}, "nonce", h.admission.Binding.SessionID)
	require.NoError(t, err)
	withoutProfileClaims := &sessionTokenClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(withoutProfile.IDToken, withoutProfileClaims)
	require.NoError(t, err)
	require.Nil(t, withoutProfileClaims.Identifiers)
	info = h.service.userInfo(h.admission, []string{oidc.ScopeOpenID, oidc.ScopeProfile})
	encoded, err = json.Marshal(info)
	require.NoError(t, err)
	var object map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &object))
	require.JSONEq(t, `{"version":1,"login":"Canonical"}`, string(object["authhub_identifiers"]))
	require.NotContains(t, object, "login")
	require.NotContains(t, object, "email_alias")
	require.NotContains(t, object, "roles")
}

func TestSessionCanonicalIdentifiersValidation(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]*oidc.CanonicalIdentifiers{
		"absent":        nil,
		"login":         {Version: 1, Login: "Main.Admin-1_name"},
		"alias":         {Version: 1, Login: "Main", EmailAlias: "first.last+tag@example.test"},
		"maximum login": {Version: 1, Login: strings.Repeat("a", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.True(t, validCanonicalIdentifiers(value))
		})
	}
	for name, value := range map[string]oidc.CanonicalIdentifiers{
		"version missing":      {Login: "Main"},
		"version future":       {Version: 2, Login: "Main"},
		"login missing":        {Version: 1, EmailAlias: "admin@example.test"},
		"login too long":       {Version: 1, Login: strings.Repeat("a", 65)},
		"login whitespace":     {Version: 1, Login: " Main"},
		"login unicode":        {Version: 1, Login: "Админ"},
		"login punctuation":    {Version: 1, Login: ".Main"},
		"alias uppercase":      {Version: 1, Login: "Main", EmailAlias: "Admin@example.test"},
		"alias whitespace":     {Version: 1, Login: "Main", EmailAlias: "admin@example.test "},
		"alias malformed":      {Version: 1, Login: "Main", EmailAlias: "a..b@example.test"},
		"alias unicode":        {Version: 1, Login: "Main", EmailAlias: "a@пример.test"},
		"alias local too long": {Version: 1, Login: "Main", EmailAlias: strings.Repeat("a", 65) + "@example.test"},
		"alias too long":       {Version: 1, Login: "Main", EmailAlias: "a@" + strings.Repeat("b.", 126) + "c"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.False(t, validCanonicalIdentifiers(&value))
			h := newSessionFixture(t)
			h.admission.Projection.Identifiers = &value
			require.False(t, validProjection(h.admission.Projection))
			response, _, _, err := h.service.prepareTokens(context.Background(), h.admission,
				h.admission.Binding, []string{oidc.ScopeOpenID, oidc.ScopeProfile}, "nonce", h.admission.Binding.SessionID)
			require.Error(t, err)
			require.Nil(t, response)
		})
	}
}
