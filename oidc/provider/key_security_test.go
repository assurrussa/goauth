//nolint:testpackage // Exercises configured key stores through full provider flows.
package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const weakSigningKeyID = "weak"

func TestPublicClientsRequirePKCERegardlessOfFlag(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"", oidc.TokenEndpointAuthMethodNone} {
		for _, direct := range []bool{false, true} {
			t.Run(method+map[bool]string{false: " hosted", true: " direct"}[direct], func(t *testing.T) {
				t.Parallel()
				h := newOIDCTestHarness(t)
				h.client.RequirePKCE = false
				h.client.TokenEndpointAuthMethod = method
				updatePolicyClient(t, h)
				var current *oidc.AuthenticatedSubject
				if direct {
					current = &oidc.AuthenticatedSubject{Account: h.subject, AuthenticatedAt: h.now}
				}
				req := oidc.AuthorizeRequest{
					ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0],
					ResponseType: responseTypeCode, Scope: oidc.ScopeOpenID,
				}
				result, err := h.service.Authorize(context.Background(), req, current)
				require.NoError(t, err)
				target, err := url.Parse(result.RedirectURI)
				require.NoError(t, err)
				require.Equal(t, "invalid_request", target.Query().Get("error"))
				require.Empty(t, h.codes.items)
				require.Empty(t, h.requests.items)
				req.CodeChallenge, req.CodeChallengeMethod = codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256
				result, err = h.service.Authorize(context.Background(), req, current)
				require.NoError(t, err)
				target, err = url.Parse(result.RedirectURI)
				require.NoError(t, err)
				if !direct {
					result, err = h.service.ContinueAuthorization(context.Background(), target.Query().Get("oidc_challenge"),
						&oidc.AuthenticatedSubject{Account: h.subject, AuthenticatedAt: h.now})
					require.NoError(t, err)
					target, err = url.Parse(result.RedirectURI)
					require.NoError(t, err)
				}
				code := target.Query().Get("code")
				require.NotEmpty(t, code)
				_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
					GrantType: grantTypeAuthorizationCode, Code: code, RedirectURI: h.client.RedirectURIs[0],
					ClientID: h.client.ID, CodeVerifier: testPKCEVerifier,
				})
				require.NoError(t, err)
			})
		}
	}
}

func TestPublicClientRejectsPersistedCodeWithoutPKCE(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	h.client.RequirePKCE = false
	updatePolicyClient(t, h)
	code := hostedAuthorizationCode(t, h, codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256)
	record := h.codes.items[code]
	record.CodeChallenge, record.CodeChallengeMethod = "", ""
	require.NoError(t, h.codes.Save(context.Background(), record))
	_, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: code, RedirectURI: h.client.RedirectURIs[0], ClientID: h.client.ID,
	})
	requireOAuthError(t, err, "invalid_grant")
}

func TestConfidentialAuthorizationWithoutPKCE(t *testing.T) {
	t.Parallel()
	for _, method := range []string{oidc.TokenEndpointAuthMethodClientSecretBasic, oidc.TokenEndpointAuthMethodClientSecretPost} {
		for _, direct := range []bool{false, true} {
			t.Run(method+map[bool]string{false: " hosted", true: " direct"}[direct], func(t *testing.T) {
				t.Parallel()
				h := newOIDCTestHarness(t)
				h.client.Secret, h.client.TokenEndpointAuthMethod, h.client.RequirePKCE = testStoredClientSecret, method, false
				updatePolicyClient(t, h)
				service, err := New(providerOptions(h))
				require.NoError(t, err)
				h.service = service
				var code string
				if direct {
					result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
						ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0], ResponseType: responseTypeCode, Scope: oidc.ScopeOpenID,
					}, &oidc.AuthenticatedSubject{Account: h.subject, AuthenticatedAt: h.now})
					require.NoError(t, err)
					target, err := url.Parse(result.RedirectURI)
					require.NoError(t, err)
					code = target.Query().Get("code")
				} else {
					code = hostedAuthorizationCode(t, h, "", "")
				}
				require.NotEmpty(t, code)
				_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
					GrantType: grantTypeAuthorizationCode, Code: code, RedirectURI: h.client.RedirectURIs[0],
					ClientID: h.client.ID, ClientSecret: testStoredClientSecret, ClientAuthMethod: method,
				})
				require.NoError(t, err)
			})
		}
	}
}

func TestTypedNilSecretVerifierDeniesConfidentialAuthentication(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	h.client.Secret, h.client.RequirePKCE = testStoredClientSecret, false
	updatePolicyClient(t, h)
	opts := providerOptions(h)
	opts.ClientSecretVerifier = oidc.ClientSecretVerifierFunc(nil)
	var err error
	h.service, err = New(opts)
	require.NoError(t, err)
	code := hostedAuthorizationCode(t, h, "", "")
	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: code, RedirectURI: h.client.RedirectURIs[0],
		ClientID: h.client.ID, ClientSecret: testStoredClientSecret, ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
	})
	requireOAuthError(t, err, "invalid_client")
	require.NotContains(t, err.Error(), testStoredClientSecret)
	require.Contains(t, h.codes.items, code)
}

func TestProviderRejectsInvalidSigningKeys(t *testing.T) {
	t.Parallel()
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Deliberately weak rejection fixture.
	require.NoError(t, err)
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	noExponent := *strong
	noExponent.E = 0
	noD := *strong
	noD.D = nil
	noPrime := *strong
	noPrime.Primes = []*big.Int{nil, strong.Primes[1]}
	for _, tc := range []struct {
		name    string
		private *rsa.PrivateKey
		public  *rsa.PublicKey
	}{
		{name: weakSigningKeyID, private: weak, public: &weak.PublicKey},
		{name: "mismatch", private: strong, public: &other.PublicKey},
		{name: "nil private", public: &strong.PublicKey},
		{name: "private invalid exponent", private: &noExponent, public: &strong.PublicKey},
		{name: "private missing D", private: &noD, public: &strong.PublicKey},
		{name: "private missing prime", private: &noPrime, public: &strong.PublicKey},
		{name: "nil public", private: strong},
		{name: "nil modulus", private: strong, public: &rsa.PublicKey{E: 65537}},
		{name: "invalid exponent", private: strong, public: &rsa.PublicKey{N: strong.N, E: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newOIDCTestHarness(t)
			h.keys.keys[h.keys.activeID] = oidc.SigningKey{ID: h.keys.activeID, PrivateKey: tc.private, PublicKey: tc.public}
			code := hostedAuthorizationCode(t, h, codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256)
			response, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, RedirectURI: h.client.RedirectURIs[0],
				ClientID: h.client.ID, CodeVerifier: testPKCEVerifier,
			})
			require.Error(t, err)
			require.Nil(t, response)
		})
	}
}

func TestProviderKeyStrengthAcrossIssuanceParsingAndJWKS(t *testing.T) {
	t.Parallel()
	for _, bits := range []int{2048, 3072} {
		t.Run(map[int]string{2048: "2048", 3072: "3072"}[bits], func(t *testing.T) {
			t.Parallel()
			h := newOIDCTestHarness(t)
			key, err := rsa.GenerateKey(rand.Reader, bits)
			require.NoError(t, err)
			require.NoError(t, h.keys.addKey(h.keys.activeID, key))
			code := hostedAuthorizationCode(t, h, codeChallengeFor(testPKCEVerifier), codeChallengeMethodS256)
			response, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, RedirectURI: h.client.RedirectURIs[0],
				ClientID: h.client.ID, CodeVerifier: testPKCEVerifier,
			})
			require.NoError(t, err)
			_, err = h.service.UserInfo(context.Background(), response.AccessToken)
			require.NoError(t, err)
			_, err = h.service.JWKS(context.Background())
			require.NoError(t, err)
		})
	}
}

func TestProviderRejectsWeakAlternateParsingKeyAndJWKS(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Deliberately weak rejection fixture.
	require.NoError(t, err)
	h.keys.keys[weakSigningKeyID] = oidc.SigningKey{ID: weakSigningKeyID, PrivateKey: weak, PublicKey: &weak.PublicKey}
	claims := accessTokenClaims{TokenUse: tokenUseAccess, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: testProviderIssuer, Subject: h.subject.Subject.ID.String(),
		ExpiresAt: jwt.NewNumericDate(h.now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(h.now),
	}}
	for _, kid := range []string{weakSigningKeyID, ""} {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		if kid != "" {
			token.Header["kid"] = kid
		} else {
			h.keys.activeID = weakSigningKeyID
		}
		signed, err := token.SignedString(weak)
		require.NoError(t, err)
		_, err = h.service.UserInfo(context.Background(), signed)
		requireOAuthError(t, err, "invalid_token")
	}
	h.keys.jwks = []oidc.JWK{{Kty: "RSA", Kid: weakSigningKeyID, E: "AQAB", N: base64.RawURLEncoding.EncodeToString(weak.N.Bytes())}}
	_, err = h.service.JWKS(context.Background())
	require.Error(t, err)
	h.keys.jwks[0].N = ""
	_, err = h.service.JWKS(context.Background())
	require.Error(t, err)
}

func TestProviderParsingRejectsMalformedPublicKeys(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	signed, err := h.service.signAccessToken(context.Background(), h.subject, h.client.ID, []string{oidc.ScopeOpenID})
	require.NoError(t, err)
	key := h.keys.keys[h.keys.activeID]
	for _, public := range []*rsa.PublicKey{nil, {E: 65537}, {N: key.PublicKey.N, E: 0}} {
		altered := key
		altered.PublicKey = public
		h.keys.keys[h.keys.activeID] = altered
		_, err := h.service.UserInfo(context.Background(), signed)
		requireOAuthError(t, err, "invalid_token")
	}
}
