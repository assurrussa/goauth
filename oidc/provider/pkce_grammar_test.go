//nolint:testpackage // Exercises PKCE input validation through the provider flow fixtures.
package provider

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

// RFC 7636 Appendix B supplies a known S256 verifier/challenge pair.
const (
	rfcPKCEVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcPKCEChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestPKCEVerifierGrammarAtExchange(t *testing.T) {
	for _, tc := range []struct {
		name, verifier string
		valid          bool
	}{
		{name: "RFC vector", verifier: rfcPKCEVerifier, valid: true},
		{name: "maximum length", verifier: strings.Repeat("aB0-._~", 18) + "AB", valid: true},
		{name: "too short", verifier: "proof"},
		{name: "below minimum", verifier: strings.Repeat("a", 42)},
		{name: "above maximum", verifier: strings.Repeat("a", 129)},
		{name: "leading whitespace", verifier: " " + rfcPKCEVerifier},
		{name: "trailing whitespace", verifier: rfcPKCEVerifier + "\n"},
		{name: "internal whitespace", verifier: strings.Repeat("a", 42) + " "},
		{name: "unicode", verifier: strings.Repeat("a", 42) + "é"},
		{name: "reserved character", verifier: strings.Repeat("a", 42) + "+"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOIDCTestHarness(t)
			challenge := codeChallengeFor(tc.verifier)
			if tc.name == "leading whitespace" || tc.name == "trailing whitespace" {
				challenge = rfcPKCEChallenge // Must not normalize a submitted secret to the valid verifier.
			}
			code := hostedAuthorizationCode(t, h, challenge, codeChallengeMethodS256)
			response, err := h.service.ExchangeToken(t.Context(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
				RedirectURI: h.client.RedirectURIs[0], CodeVerifier: tc.verifier,
			})
			if tc.valid {
				require.NoError(t, err)
				require.NotEmpty(t, response.AccessToken)
			} else {
				requireOAuthError(t, err, "invalid_grant")
				require.Nil(t, response)
				require.Empty(t, h.refreshTokens.items)
			}
		})
	}
	require.True(t, verifyCodeVerifier(rfcPKCEVerifier, rfcPKCEChallenge))
}

func TestPKCEChallengeGrammarAtAuthorizationAndExchange(t *testing.T) {
	for _, challenge := range []string{
		"proof", rfcPKCEChallenge[:42], rfcPKCEChallenge + "A", rfcPKCEChallenge + "=",
		" " + rfcPKCEChallenge, rfcPKCEChallenge + "\n",
		"+" + rfcPKCEChallenge[1:], "/" + rfcPKCEChallenge[1:],
		rfcPKCEChallenge[:42] + "N", // Same decoded digest with nonzero unused base64 bits.
	} {
		t.Run(challenge, func(t *testing.T) {
			h := newOIDCTestHarness(t)
			result, err := h.service.Authorize(t.Context(), oidc.AuthorizeRequest{
				ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0], ResponseType: responseTypeCode,
				Scope: oidc.ScopeOpenID, CodeChallenge: challenge, CodeChallengeMethod: codeChallengeMethodS256,
			}, nil)
			require.NoError(t, err)
			target, err := url.Parse(result.RedirectURI)
			require.NoError(t, err)
			require.Equal(t, "invalid_request", target.Query().Get("error"))
			require.Empty(t, h.requests.items)
			require.Empty(t, h.codes.items)
			code := hostedAuthorizationCode(t, h, rfcPKCEChallenge, codeChallengeMethodS256)
			record := h.codes.items[code]
			record.CodeChallenge = challenge
			h.codes.items[code] = record
			response, err := h.service.ExchangeToken(t.Context(), oidc.TokenRequest{
				GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
				RedirectURI: h.client.RedirectURIs[0], CodeVerifier: rfcPKCEVerifier,
			})
			requireOAuthError(t, err, "invalid_grant")
			require.Nil(t, response)
			require.Empty(t, h.refreshTokens.items)
		})
	}
}
