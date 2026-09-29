//nolint:testpackage // Verifies the provider's exact issuer identity.
package provider

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestProviderPreservesConfiguredIssuer(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	for _, testCase := range []struct {
		name       string
		configured string
		issuer     string
	}{
		{"plain", testProviderIssuer, testProviderIssuer},
		{"trailing_slash", testProviderIssuer + "/", testProviderIssuer + "/"},
		{"whitespace", " \t" + testProviderIssuer + "\n ", testProviderIssuer},
		{"whitespace_and_trailing_slash", " \t" + testProviderIssuer + "/\n ", testProviderIssuer + "/"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			service, err := New(Options{
				Clients: h.service.clients, Requests: h.requests, Codes: h.codes,
				RefreshTokens: h.refreshTokens, Keys: h.keys, Claims: h.service.claims, Issuer: testCase.configured,
			})
			require.NoError(t, err)
			t.Run("discovery", func(t *testing.T) {
				discovery := service.Discovery(context.Background())
				require.Equal(t, testCase.issuer, discovery.Issuer)
			})
			t.Run("endpoints", func(t *testing.T) {
				discovery := service.Discovery(context.Background())
				require.Equal(t, testProviderIssuer+"/oauth2/authorize", discovery.AuthorizationEndpoint)
				require.Equal(t, testProviderIssuer+"/oauth2/token", discovery.TokenEndpoint)
				require.Equal(t, testProviderIssuer+"/oauth2/userinfo", discovery.UserInfoEndpoint)
				require.Equal(t, testProviderIssuer+"/oauth2/jwks", discovery.JWKSURI)
				require.Equal(t, testProviderIssuer+"/oauth2/revoke", discovery.RevocationEndpoint)
			})
			accessToken, err := service.signAccessToken(context.Background(), h.subject, h.client.ID,
				[]string{oidc.ScopeOpenID})
			require.NoError(t, err)
			idToken, err := service.signIDToken(context.Background(), h.subject, h.client.ID,
				[]string{oidc.ScopeOpenID}, h.now, "")
			require.NoError(t, err)
			for _, tokenCase := range []struct {
				name  string
				token string
			}{
				{"access_token", accessToken},
				{"id_token", idToken},
			} {
				t.Run(tokenCase.name, func(t *testing.T) {
					claims := &jwt.RegisteredClaims{}
					parsed, err := jwt.ParseWithClaims(tokenCase.token, claims, func(_ *jwt.Token) (any, error) {
						key, keyErr := h.keys.Active(context.Background())
						return key.PublicKey, keyErr
					})
					require.NoError(t, err)
					require.True(t, parsed.Valid)
					require.Equal(t, testCase.issuer, claims.Issuer)
				})
			}
		})
	}
}
