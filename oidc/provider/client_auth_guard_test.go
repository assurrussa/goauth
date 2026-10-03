//nolint:testpackage // Tests the provider's authentication guard without issuing tokens.
package provider

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestConfidentialClientAuthenticationConfiguration(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	const verifierSecret = " verifier-owned-secret " //nolint:gosec // Synthetic verifier fixture, not a credential.
	verifier := oidc.ClientSecretVerifierFunc(func(_ context.Context, clientID, secret string) error {
		if clientID == h.client.ID && secret == verifierSecret {
			return nil
		}
		return errors.New("client credentials rejected")
	})
	cases := []struct {
		name              string
		configuredSecret  string
		presentedSecret   string
		verifier          oidc.ClientSecretVerifier
		wantAuthenticated bool
	}{
		{name: "unconfigured static secret"},
		{name: "unconfigured static secret with whitespace credentials", presentedSecret: " \t "},
		{name: "unconfigured static secret with supplied credentials", presentedSecret: testStoredClientSecret},
		{name: "blank static secret", configuredSecret: " \t "},
		{name: "nil verifier function", verifier: oidc.ClientSecretVerifierFunc(nil)},
		{
			name: "valid static secret", configuredSecret: testStoredClientSecret,
			presentedSecret: testStoredClientSecret, wantAuthenticated: true,
		},
		{
			name: "static secret preserves credential trimming", configuredSecret: testStoredClientSecret,
			presentedSecret: " " + testStoredClientSecret + " ", wantAuthenticated: true,
		},
		{name: "missing static credentials", configuredSecret: testStoredClientSecret},
		{
			name: "incorrect static credentials", configuredSecret: testStoredClientSecret,
			presentedSecret: "incorrect-secret",
		},
		{
			name: "verifier without static secret", verifier: verifier,
			presentedSecret: verifierSecret, wantAuthenticated: true,
		},
		{
			name: "verifier with legacy static secret", configuredSecret: testStoredClientSecret,
			verifier: verifier, presentedSecret: verifierSecret, wantAuthenticated: true,
		},
		{
			name: "verifier rejection has no static fallback", configuredSecret: testStoredClientSecret,
			verifier: verifier, presentedSecret: testStoredClientSecret,
		},
		{
			name: "nil verifier has no static fallback", configuredSecret: testStoredClientSecret,
			verifier: oidc.ClientSecretVerifierFunc(nil), presentedSecret: testStoredClientSecret,
		},
	}
	for _, method := range []string{oidc.TokenEndpointAuthMethodClientSecretBasic, oidc.TokenEndpointAuthMethodClientSecretPost} {
		for _, tc := range cases {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				client := oidc.Client{ID: h.client.ID, Secret: tc.configuredSecret, TokenEndpointAuthMethod: method}
				opts := providerOptions(h)
				opts.Clients = &memoryClientStore{items: map[string]oidc.Client{client.ID: client}}
				opts.ClientSecretVerifier = tc.verifier
				svc, err := New(opts)
				require.NoError(t, err)

				authenticated, err := svc.authenticateClient(context.Background(), client.ID, tc.presentedSecret, method)
				if tc.wantAuthenticated {
					require.NoError(t, err)
					require.Equal(t, client, authenticated)
					return
				}
				requireOAuthError(t, err, "invalid_client")
				var oauthErr *oidc.OAuthError
				require.ErrorAs(t, err, &oauthErr)
				require.Equal(t, http.StatusUnauthorized, oauthErr.StatusCode)
				require.Empty(t, authenticated)
			})
		}
	}
}

func TestClientAuthenticationUsesGetOnlyRegistry(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	client := oidc.Client{
		ID: h.client.ID, Secret: testStoredClientSecret,
		TokenEndpointAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
	}
	lookups := 0
	opts := providerOptions(h)
	opts.Clients = clientAuthGuardStoreFunc(func(ctx context.Context, clientID string) (oidc.Client, error) {
		require.NoError(t, ctx.Err())
		require.Equal(t, client.ID, clientID)
		lookups++
		return client, nil
	})
	svc, err := New(opts)
	require.NoError(t, err)
	require.Zero(t, lookups, "provider construction must not inspect a Get-only registry")

	authenticated, err := svc.authenticateClient(context.Background(), client.ID, client.Secret, client.TokenEndpointAuthMethod)
	require.NoError(t, err)
	require.Equal(t, client, authenticated)
	require.Equal(t, 1, lookups)
}

type clientAuthGuardStoreFunc func(context.Context, string) (oidc.Client, error)

func (f clientAuthGuardStoreFunc) Get(ctx context.Context, clientID string) (oidc.Client, error) {
	return f(ctx, clientID)
}
