//nolint:testpackage // Verifies the provider's exact issuer identity.
package provider

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestProviderPreservesConfiguredIssuer(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	issuer := testProviderIssuer + "/"
	service, err := New(Options{
		Clients: h.service.clients, Requests: h.requests, Codes: h.codes,
		RefreshTokens: h.refreshTokens, Keys: h.keys, Claims: h.service.claims, Issuer: issuer,
	})
	require.NoError(t, err)
	discovery := service.Discovery(context.Background())
	require.Equal(t, issuer, discovery.Issuer)
	require.Equal(t, testProviderIssuer+"/oauth2/token", discovery.TokenEndpoint)
	token, err := service.signAccessToken(context.Background(), h.subject, h.client.ID, nil)
	require.NoError(t, err)
	claims := &jwt.RegisteredClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	require.Equal(t, issuer, claims.Issuer)
}
