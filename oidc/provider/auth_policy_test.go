//nolint:testpackage // Regression tests reuse the provider's in-memory flow fixtures.
package provider

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const (
	testPKCEVerifier       = rfcPKCEVerifier
	testPKCEPlain          = "plain"
	testUnknownAuthMethod  = "unknown"
	testStoredClientSecret = "stored-secret"
)

func updatePolicyClient(t *testing.T, h *oidcTestHarness) {
	t.Helper()
	store, ok := h.service.clients.(*memoryClientStore)
	require.True(t, ok)
	store.items[h.client.ID] = h.client
}

func providerOptions(h *oidcTestHarness) Options {
	return Options{
		Clients: h.service.clients, Requests: h.requests, Codes: h.codes,
		RefreshTokens: h.refreshTokens, Keys: h.keys, Claims: h.service.claims,
		Issuer: testProviderIssuer, Now: func() time.Time { return h.now }, GenerateToken: h.service.generateToken,
	}
}

func hostedAuthorizationCode(t *testing.T, h *oidcTestHarness, challenge, method string) string {
	t.Helper()
	result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0], ResponseType: responseTypeCode,
		Scope: "openid offline_access", CodeChallenge: challenge, CodeChallengeMethod: method,
	}, nil)
	require.NoError(t, err)
	target, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	require.Empty(t, target.Query().Get("error"))
	result, err = h.service.ContinueAuthorization(context.Background(), target.Query().Get("oidc_challenge"),
		&oidc.AuthenticatedSubject{Account: h.subject, AuthenticatedAt: h.now})
	require.NoError(t, err)
	target, err = url.Parse(result.RedirectURI)
	require.NoError(t, err)
	code := target.Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

func TestPKCEPolicyAuthorizationAndExchange(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                          string
		required                      bool
		challenge, method, verifier   string
		authorizeError, exchangeError bool
	}{
		{name: "optional absent"},
		{
			name: "optional S256", challenge: codeChallengeFor(testPKCEVerifier),
			method: codeChallengeMethodS256, verifier: testPKCEVerifier,
		},
		{
			name: "optional wrong verifier", challenge: codeChallengeFor(testPKCEVerifier),
			method: codeChallengeMethodS256, verifier: "0" + testPKCEVerifier[1:],
			exchangeError: true,
		},
		{
			name: "optional missing verifier", challenge: codeChallengeFor(testPKCEVerifier), method: codeChallengeMethodS256,
			exchangeError: true,
		},
		{name: "method without challenge", method: codeChallengeMethodS256, authorizeError: true},
		{name: "plain forbidden", challenge: testPKCEVerifier, method: testPKCEPlain, verifier: testPKCEVerifier, authorizeError: true},
		{name: "challenge without method", challenge: codeChallengeFor(testPKCEVerifier), authorizeError: true},
		{name: "required absent", required: true, authorizeError: true},
		{
			name: "required S256", required: true,
			challenge: codeChallengeFor(testPKCEVerifier), method: codeChallengeMethodS256, verifier: testPKCEVerifier,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newOIDCTestHarness(t)
			h.client.RequirePKCE = tc.required
			h.client.Secret = testStoredClientSecret
			updatePolicyClient(t, h)
			service, err := New(providerOptions(h))
			require.NoError(t, err)
			h.service = service
			if tc.authorizeError {
				result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
					ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0], ResponseType: responseTypeCode,
					Scope: oidc.ScopeOpenID, CodeChallenge: tc.challenge, CodeChallengeMethod: tc.method,
				}, nil)
				require.NoError(t, err)
				target, err := url.Parse(result.RedirectURI)
				require.NoError(t, err)
				require.Equal(t, "invalid_request", target.Query().Get("error"))
				require.Empty(t, h.requests.items)
				require.Empty(t, h.codes.items)
				return
			}
			code := hostedAuthorizationCode(t, h, tc.challenge, tc.method)
			response, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
				RedirectURI: h.client.RedirectURIs[0], CodeVerifier: tc.verifier,
				ClientSecret: testStoredClientSecret, ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
			})
			if tc.exchangeError {
				requireOAuthError(t, err, "invalid_grant")
				return
			}
			require.NoError(t, err)
			info, err := h.service.UserInfo(context.Background(), response.AccessToken)
			require.NoError(t, err)
			require.Equal(t, h.subject.Subject.ID.String(), info.Subject)
		})
	}
}

func TestExchangeRejectsCorruptPKCEMetadata(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, challenge, method string
		required                bool
	}{
		{name: testPKCEPlain, challenge: codeChallengeFor(testPKCEVerifier), method: testPKCEPlain},
		{name: "method missing", challenge: codeChallengeFor(testPKCEVerifier)},
		{name: "challenge missing", method: codeChallengeMethodS256},
		{name: "required metadata removed", required: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newOIDCTestHarness(t)
			h.client.RequirePKCE = tc.required
			updatePolicyClient(t, h)
			code := hostedAuthorizationCode(t, h, codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256)
			record := h.codes.items[code]
			record.CodeChallenge, record.CodeChallengeMethod = tc.challenge, tc.method
			require.NoError(t, h.codes.Save(context.Background(), record))
			_, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
				RedirectURI: h.client.RedirectURIs[0], CodeVerifier: testPKCEVerifier,
			})
			requireOAuthError(t, err, "invalid_grant")
		})
	}
}

func TestProviderAuthMethodsConfigurationAndEnforcement(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	for _, methods := range [][]string{{}, {""}, {" "}, {testUnknownAuthMethod}, {"none", testUnknownAuthMethod}, {" none "}} {
		opts := providerOptions(h)
		opts.TokenEndpointAuthMethods = methods
		_, err := New(opts)
		require.Error(t, err)
	}
	opts := providerOptions(h)
	svc, err := New(opts)
	require.NoError(t, err)
	require.Equal(t, []string{"none", "client_secret_basic", "client_secret_post"},
		svc.Discovery(context.Background()).TokenEndpointAuthMethodsSupported)

	opts.TokenEndpointAuthMethods = []string{oidc.TokenEndpointAuthMethodClientSecretBasic}
	h.service, err = New(opts)
	require.NoError(t, err)
	require.Equal(t, opts.TokenEndpointAuthMethods, h.service.Discovery(context.Background()).TokenEndpointAuthMethodsSupported)
	code := hostedAuthorizationCode(t, h, codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256)
	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
		RedirectURI: h.client.RedirectURIs[0], CodeVerifier: testPKCEVerifier,
	})
	requireOAuthError(t, err, "invalid_client")
	require.Contains(t, h.codes.items, code)

	opts.TokenEndpointAuthMethods = nil
	h.service, err = New(opts)
	require.NoError(t, err)
	h.client.TokenEndpointAuthMethod = testUnknownAuthMethod
	updatePolicyClient(t, h)
	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
		RedirectURI: h.client.RedirectURIs[0], CodeVerifier: testPKCEVerifier,
	})
	requireOAuthError(t, err, "invalid_client")
	h.client.TokenEndpointAuthMethod = ""
	updatePolicyClient(t, h)
	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
		RedirectURI: h.client.RedirectURIs[0], CodeVerifier: testPKCEVerifier, ClientAuthMethod: testUnknownAuthMethod,
	})
	requireOAuthError(t, err, "invalid_client")
}

func TestUserInfoEnforcesAccessTokenProfile(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	// Deliberately differ from wall-clock time to prove validation uses Options.Now.
	h.now = time.Date(2040, time.January, 2, 3, 4, 5, 0, time.UTC)
	opts := providerOptions(h)
	var err error
	h.service, err = New(opts)
	require.NoError(t, err)
	key, err := h.keys.Active(context.Background())
	require.NoError(t, err)
	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
		mutate func(*accessTokenClaims)
		valid  bool
	}{
		{name: "valid RS256", method: jwt.SigningMethodRS256, valid: true},
		{name: "RS512", method: jwt.SigningMethodRS512},
		{name: "PS256", method: jwt.SigningMethodPS256},
		{name: "missing expiration", method: jwt.SigningMethodRS256, mutate: func(c *accessTokenClaims) { c.ExpiresAt = nil }},
		{name: "expired", method: jwt.SigningMethodRS256, mutate: func(c *accessTokenClaims) {
			c.ExpiresAt = jwt.NewNumericDate(h.now.Add(-time.Second))
		}},
		{name: "expiration boundary", method: jwt.SigningMethodRS256, mutate: func(c *accessTokenClaims) {
			c.ExpiresAt = jwt.NewNumericDate(h.now)
		}},
		{name: "wrong issuer", method: jwt.SigningMethodRS256, mutate: func(c *accessTokenClaims) {
			c.Issuer = "https://wrong.example"
		}},
		{name: "missing issuer", method: jwt.SigningMethodRS256, mutate: func(c *accessTokenClaims) { c.Issuer = "" }},
		{name: "missing issued at", method: jwt.SigningMethodRS256, mutate: func(c *accessTokenClaims) { c.IssuedAt = nil }},
		{name: "future issued at", method: jwt.SigningMethodRS256, mutate: func(c *accessTokenClaims) {
			c.IssuedAt = jwt.NewNumericDate(h.now.Add(time.Second))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := accessTokenClaims{TokenUse: tokenUseAccess, Scope: oidc.ScopeOpenID, RegisteredClaims: jwt.RegisteredClaims{
				Issuer: testProviderIssuer, Subject: h.subject.Subject.ID.String(),
				ExpiresAt: jwt.NewNumericDate(h.now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(h.now),
			}}
			if tc.mutate != nil {
				tc.mutate(&claims)
			}
			token := jwt.NewWithClaims(tc.method, claims)
			token.Header["kid"] = key.ID
			signed, err := token.SignedString(key.PrivateKey)
			require.NoError(t, err)
			info, err := h.service.UserInfo(context.Background(), signed)
			if !tc.valid {
				requireOAuthError(t, err, "invalid_token")
				return
			}
			require.NoError(t, err)
			require.Equal(t, h.subject.Subject.ID.String(), info.Subject)
		})
	}
}

func TestClientSecretVerifierIsAuthoritativeAcrossTokenLifecycle(t *testing.T) {
	t.Parallel()
	for _, method := range []string{oidc.TokenEndpointAuthMethodClientSecretBasic, oidc.TokenEndpointAuthMethodClientSecretPost} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			h := newOIDCTestHarness(t)
			h.client.Secret = "legacy-static-secret"
			h.client.TokenEndpointAuthMethod = method
			updatePolicyClient(t, h)
			opts := providerOptions(h)
			calls := 0
			opts.ClientSecretVerifier = oidc.ClientSecretVerifierFunc(func(ctx context.Context, clientID, secret string) error {
				require.NoError(t, ctx.Err())
				require.Equal(t, h.client.ID, clientID)
				calls++
				if secret == testStoredClientSecret {
					return nil
				}
				return errors.New("secret rejected: " + secret)
			})
			var err error
			h.service, err = New(opts)
			require.NoError(t, err)
			code := hostedAuthorizationCode(t, h, codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256)
			req := oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
				RedirectURI: h.client.RedirectURIs[0], CodeVerifier: testPKCEVerifier,
				ClientAuthMethod: method, ClientSecret: h.client.Secret,
			}
			_, err = h.service.ExchangeToken(context.Background(), req)
			requireOAuthError(t, err, "invalid_client")
			require.NotContains(t, err.Error(), h.client.Secret)
			require.Contains(t, h.codes.items, code)
			req.ClientSecret = testStoredClientSecret
			response, err := h.service.ExchangeToken(context.Background(), req)
			require.NoError(t, err)
			req = oidc.TokenRequest{
				GrantType: grantTypeRefreshToken, RefreshToken: response.RefreshToken,
				ClientID: h.client.ID, ClientAuthMethod: method, ClientSecret: h.client.Secret,
			}
			_, err = h.service.ExchangeToken(context.Background(), req)
			requireOAuthError(t, err, "invalid_client")
			req.ClientSecret = testStoredClientSecret
			response, err = h.service.ExchangeToken(context.Background(), req)
			require.NoError(t, err)
			revoke := oidc.RevokeRequest{
				Token: response.RefreshToken, ClientID: h.client.ID,
				ClientAuthMethod: method, ClientSecret: h.client.Secret,
			}
			err = h.service.Revoke(context.Background(), revoke)
			requireOAuthError(t, err, "invalid_client")
			revoke.ClientSecret = testStoredClientSecret
			require.NoError(t, h.service.Revoke(context.Background(), revoke))
			record, err := h.refreshTokens.Get(context.Background(), response.RefreshToken)
			require.NoError(t, err)
			require.NotNil(t, record.RevokedAt)
			require.Equal(t, 6, calls)
		})
	}
}

func TestPublicClientSkipsSecretVerifier(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	opts := providerOptions(h)
	opts.ClientSecretVerifier = oidc.ClientSecretVerifierFunc(func(context.Context, string, string) error {
		t.Fatal("none authentication must not consult the secret verifier")
		return errors.New("unexpected verification")
	})
	var err error
	h.service, err = New(opts)
	require.NoError(t, err)
	code := hostedAuthorizationCode(t, h, codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256)
	response, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
		RedirectURI: h.client.RedirectURIs[0], CodeVerifier: testPKCEVerifier,
	})
	require.NoError(t, err)
	response, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeRefreshToken, RefreshToken: response.RefreshToken, ClientID: h.client.ID,
	})
	require.NoError(t, err)
	require.NoError(t, h.service.Revoke(context.Background(), oidc.RevokeRequest{
		Token: response.RefreshToken, ClientID: h.client.ID,
	}))
}
