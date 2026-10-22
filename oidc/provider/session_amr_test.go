//nolint:testpackage // Exercises private signed claim and preparation boundaries.
package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const (
	testAMROTP      = "otp"
	testAMRPassword = "pwd"
	testAMRMFA      = "mfa"
)

func verifySessionAMR(t *testing.T, h *sessionFixture, raw string) *sessionTokenClaims {
	t.Helper()
	key, err := h.keys.Active(t.Context())
	require.NoError(t, err)
	claims := &sessionTokenClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
		return key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(h.service.base.issuer),
		jwt.WithAudience(h.admission.Client.ID), jwt.WithTimeFunc(h.service.now), jwt.WithExpirationRequired())
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	return claims
}

func TestSessionAuthenticationMethodsSignedAndRefreshed(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Authentication = &oidc.SessionAuthentication{
		AuthenticatedAt: h.admission.Binding.AuthenticatedAt,
		Methods:         []string{testAMRPassword, testAMROTP, testAMRPassword},
	}
	request := h.authorizeRequest()
	request.Scope = oidc.ScopeOpenID
	result, err := h.service.Authorize(t.Context(), request, h.browser())
	require.NoError(t, err)
	// The ordinary exchange path signs AMR even without the profile scope.
	callback, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	code := callback.Query().Get("code")
	response, err := h.service.ExchangeToken(t.Context(), h.codeRequest(code))
	require.NoError(t, err)
	claims := verifySessionAMR(t, h, response.IDToken)
	require.NotNil(t, claims.AMR)
	require.Equal(t, []string{testAMRPassword, testAMROTP}, *claims.AMR)
	require.Equal(t, h.admission.Binding.AuthenticatedAt.Unix(), claims.AuthTime)
	h.admission.Authentication.Methods[0] = testAMRMFA
	require.Equal(t, []string{testAMRPassword, testAMROTP}, *claims.AMR)
	// Restore the immutable authentication-event snapshot before refresh.
	h.admission.Authentication.Methods[0] = testAMRPassword
	refreshed, err := h.service.ExchangeToken(t.Context(), h.refreshRequest(response.RefreshToken))
	require.NoError(t, err)
	updated := verifySessionAMR(t, h, refreshed.IDToken)
	require.Equal(t, *claims.AMR, *updated.AMR)
	require.Equal(t, claims.AuthTime, updated.AuthTime)
	access, err := h.service.parseSessionAccessToken(t.Context(), response.AccessToken)
	require.NoError(t, err)
	require.Nil(t, access.AMR)
	require.Contains(t, h.service.Discovery(t.Context()).ClaimsSupported, "amr")
}

func TestSessionAuthenticationMethodsRejectMalformedEvidence(t *testing.T) {
	t.Parallel()
	for name, methods := range map[string][]string{
		"empty method": {""},
		"space":        {"pwd otp"}, "prefix space": {" pwd"}, "control": {"pwd\n"},
		"unicode": {"пароль"}, "punctuation": {"pwd,otp"}, "long method": {strings.Repeat("a", 65)},
		"too many": make([]string, 17),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			h.admission.Authentication = &oidc.SessionAuthentication{
				AuthenticatedAt: h.admission.Binding.AuthenticatedAt, Methods: methods,
			}
			code := h.authorizeCode(t)
			response, err := h.service.ExchangeToken(t.Context(), h.codeRequest(code))
			require.Error(t, err)
			require.Nil(t, response)
			require.Nil(t, h.codes[code].ConsumedAt, "bad evidence must not burn a code")
			require.Empty(t, h.tokens)
		})
	}
}

func TestSessionAuthenticationMethodsCannotMixAuthenticationEvents(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Authentication = &oidc.SessionAuthentication{
		AuthenticatedAt: h.admission.Binding.AuthenticatedAt, Methods: []string{testAMRPassword},
	}
	response := h.issue(t)
	h.now = h.now.Add(time.Minute)
	h.admission.Binding.AuthenticatedAt = h.now
	h.admission.Authentication = &oidc.SessionAuthentication{AuthenticatedAt: h.now, Methods: []string{testAMRPassword, testAMROTP}}
	refreshed, err := h.service.ExchangeToken(t.Context(), h.refreshRequest(response.RefreshToken))
	require.Error(t, err)
	require.Nil(t, refreshed)
	require.Nil(t, h.tokens[response.RefreshToken].ConsumedAt, "bad evidence must not rotate refresh")
	// Hosts may return the original persisted event even after a later login.
	h.admission.Authentication.AuthenticatedAt = h.now.Add(-time.Minute)
	h.admission.Authentication.Methods = []string{testAMRPassword}
	refreshed, err = h.service.ExchangeToken(t.Context(), h.refreshRequest(response.RefreshToken))
	require.NoError(t, err)
	claims := verifySessionAMR(t, h, refreshed.IDToken)
	require.Equal(t, []string{testAMRPassword}, *claims.AMR)
	require.Equal(t, h.admission.Authentication.AuthenticatedAt.Unix(), claims.AuthTime)
}

func TestSessionAuthenticationMethodsNeverInferFromEnrollment(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Projection.MFA = &oidc.MFAEnrollment{Version: 1, Enrolled: true, SetupAvailable: true}
	claims := verifySessionAMR(t, h, h.issue(t).IDToken)
	require.Nil(t, claims.AMR)
	methods, err := sessionAuthenticationMethods(&oidc.SessionAuthentication{Methods: []string{testAMRPassword}}, h.now)
	require.Error(t, err)
	require.Nil(t, methods)
}

func TestSessionAuthenticationMethodsCopyAndBounds(t *testing.T) {
	t.Parallel()
	now := time.Now()
	evidence := &oidc.SessionAuthentication{
		AuthenticatedAt: now, Methods: []string{testAMRPassword, testAMROTP, testAMRPassword, "custom-1_A"},
	}
	methods, err := sessionAuthenticationMethods(evidence, now)
	require.NoError(t, err)
	require.Equal(t, []string{testAMRPassword, testAMROTP, "custom-1_A"}, *methods)
	evidence.Methods[0] = testAMRMFA
	require.Equal(t, testAMRPassword, (*methods)[0])
	evidence.Methods = []string{strings.Repeat("a", 64)}
	_, err = sessionAuthenticationMethods(evidence, now)
	require.NoError(t, err)
}

func TestSessionAuthenticationMethodsExplicitEmpty(t *testing.T) {
	t.Parallel()
	for _, methods := range [][]string{nil, {}} {
		h := newSessionFixture(t)
		h.admission.Authentication = &oidc.SessionAuthentication{AuthenticatedAt: h.admission.Binding.AuthenticatedAt, Methods: methods}
		claims := verifySessionAMR(t, h, h.issue(t).IDToken)
		require.NotNil(t, claims.AMR)
		require.Empty(t, *claims.AMR)
	}
}

func TestSessionAuthenticationMethodsRejectSameSecondMismatch(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	binding := h.admission.Binding
	h.admission.Authentication = &oidc.SessionAuthentication{
		AuthenticatedAt: binding.AuthenticatedAt.Add(time.Nanosecond), Methods: []string{testAMRPassword, testAMROTP},
	}
	require.Equal(t, binding.AuthenticatedAt.Unix(), h.admission.Authentication.AuthenticatedAt.Unix())
	response, _, _, err := h.service.prepareTokens(t.Context(), h.admission, binding,
		[]string{oidc.ScopeOpenID}, "nonce", binding.SessionID)
	require.Error(t, err)
	require.Nil(t, response)
}

func TestSessionAuthenticationMethodsMalformedTypes(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`{"Methods":"pwd"}`, `{"Methods":[1]}`, `{"Methods":[true]}`, `{"Methods":{}}`} {
		var evidence oidc.SessionAuthentication
		require.Error(t, json.Unmarshal([]byte(raw), &evidence)) //nolint:musttag // Transport-neutral DTO has no JSON tags.
	}
}

func TestSessionAuthenticationMethodsCryptographicIntegrity(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Authentication = &oidc.SessionAuthentication{AuthenticatedAt: h.now, Methods: []string{testAMRPassword}}
	response := h.issue(t)
	parts := strings.Split(response.IDToken, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	payload = bytes.Replace(payload, []byte(`"amr":["pwd"]`), []byte(`"amr":["pwd","otp","mfa"]`), 1)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	key, err := h.keys.Active(t.Context())
	require.NoError(t, err)
	_, err = jwt.Parse(strings.Join(parts, "."), func(*jwt.Token) (any, error) {
		return key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithTimeFunc(h.service.now))
	require.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}

func TestLegacyProviderDoesNotAddAuthenticationMethods(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	raw, err := h.service.signIDToken(t.Context(), h.subject, h.client.ID,
		[]string{oidc.ScopeOpenID}, h.now, "nonce")
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	key, err := h.keys.Active(t.Context())
	require.NoError(t, err)
	parsed, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) {
		return key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithTimeFunc(func() time.Time { return h.now }))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.NotContains(t, claims, "amr")
}
