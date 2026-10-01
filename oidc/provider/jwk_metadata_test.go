//nolint:testpackage // Uses a custom signing-key store to exercise provider JWKS publication.
package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestProviderJWKSRejectsIncompatibleSigningMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*oidc.JWK)
		valid  bool
	}{
		{name: "RS256 signing", valid: true},
		{name: "optional use and algorithm", mutate: func(k *oidc.JWK) { k.Use, k.Alg = "", "" }, valid: true},
		{name: "empty key id", mutate: func(k *oidc.JWK) { k.Kid = "" }},
		{name: "blank key id", mutate: func(k *oidc.JWK) { k.Kid = " \t" }},
		{name: "encryption key", mutate: func(k *oidc.JWK) { k.Use = "enc" }},
		{name: "other algorithm", mutate: func(k *oidc.JWK) { k.Alg = "RS512" }},
		{name: "other key type", mutate: func(k *oidc.JWK) { k.Kty = "EC" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOIDCTestHarness(t)
			if tc.mutate != nil {
				tc.mutate(&h.keys.jwks[0])
			}
			keys, err := h.service.JWKS(t.Context())
			if tc.valid {
				require.NoError(t, err)
				require.Len(t, keys.Keys, 1)
			} else {
				require.Error(t, err)
				require.Empty(t, keys.Keys)
			}
		})
	}
}

func TestProviderJWKSRejectsAmbiguousKeyIDs(t *testing.T) {
	h := newOIDCTestHarness(t)
	first := h.keys.jwks[0]
	h.keys.jwks = append(h.keys.jwks, first)
	keys, err := h.service.JWKS(t.Context())
	require.NoError(t, err, "identical duplicates remain compatible with the verifier")
	require.Len(t, keys.Keys, 2)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	conflict, err := oidc.EncodeRSAPublicKeyJWK(first.Kid, &other.PublicKey)
	require.NoError(t, err)
	h.keys.jwks[1] = conflict
	keys, err = h.service.JWKS(t.Context())
	require.ErrorContains(t, err, "ambiguous signing key id")
	require.Empty(t, keys.Keys)
}

func TestProviderSigningAlgorithmPolicy(t *testing.T) {
	for _, algorithm := range []string{
		"", jwt.SigningMethodRS256.Alg(), jwt.SigningMethodRS512.Alg(), jwt.SigningMethodPS256.Alg(),
	} {
		t.Run(algorithm, func(t *testing.T) {
			h := newOIDCTestHarness(t)
			key := h.keys.keys[h.keys.activeID]
			key.Algorithm = algorithm
			h.keys.keys[h.keys.activeID] = key
			code := hostedAuthorizationCode(t, h, rfcPKCEChallenge, codeChallengeMethodS256)
			response, err := h.service.ExchangeToken(t.Context(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
				RedirectURI: h.client.RedirectURIs[0], CodeVerifier: rfcPKCEVerifier,
			})
			if algorithm == "" || algorithm == jwt.SigningMethodRS256.Alg() {
				require.NoError(t, err)
				require.NotEmpty(t, response.AccessToken)
			} else {
				require.Error(t, err)
				require.Nil(t, response)
			}
		})
	}
}

func TestProviderSigningKeyRequiresID(t *testing.T) {
	for _, id := range []string{"", " \t", " signing-key "} {
		t.Run(id, func(t *testing.T) {
			h := newOIDCTestHarness(t)
			key := h.keys.keys[h.keys.activeID]
			key.ID = id
			h.keys.keys[h.keys.activeID] = key
			code := hostedAuthorizationCode(t, h, rfcPKCEChallenge, codeChallengeMethodS256)
			response, err := h.service.ExchangeToken(t.Context(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
				RedirectURI: h.client.RedirectURIs[0], CodeVerifier: rfcPKCEVerifier,
			})
			if id == " signing-key " {
				require.NoError(t, err)
				token, _, parseErr := new(jwt.Parser).ParseUnverified(response.AccessToken, jwt.MapClaims{})
				require.NoError(t, parseErr)
				require.Equal(t, id, token.Header["kid"], "valid IDs are preserved verbatim")
			} else {
				require.ErrorContains(t, err, "signing key id is required")
				require.Nil(t, response)
			}
		})
	}
}
