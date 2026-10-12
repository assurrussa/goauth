//nolint:testpackage // Exercises the signed advisory projection boundary.
package provider

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestSessionMFAAdvisorySignedAndRefreshed(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	want := &oidc.MFAEnrollment{Version: 1, SetupAvailable: true}
	h.admission.Projection.MFA = want
	response := h.issue(t)
	key, err := h.keys.Active(t.Context())
	require.NoError(t, err)
	claims := &sessionTokenClaims{}
	parsed, err := jwt.ParseWithClaims(response.IDToken, claims, func(*jwt.Token) (any, error) {
		return key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(h.service.base.issuer),
		jwt.WithAudience(h.admission.Client.ID), jwt.WithTimeFunc(h.service.now))
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.Equal(t, want, claims.MFA)
	access, err := h.service.parseSessionAccessToken(t.Context(), response.AccessToken)
	require.NoError(t, err)
	require.Nil(t, access.MFA, "advisory hint is not access-token authorization")
	want.Enrolled = true
	require.False(t, claims.MFA.Enrolled, "issued token keeps its original snapshot")
	refreshed, err := h.service.ExchangeToken(t.Context(), h.refreshRequest(response.RefreshToken))
	require.NoError(t, err)
	updated := &sessionTokenClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(refreshed.IDToken, updated)
	require.NoError(t, err)
	require.True(t, updated.MFA.Enrolled, "normal refresh takes current projection")
	require.Equal(t, claims.Subject, updated.Subject)
	require.Equal(t, claims.SessionID, updated.SessionID)
	require.Contains(t, h.service.Discovery(t.Context()).ClaimsSupported, "authhub_mfa")
}

func TestSessionMFAAdvisoryCannotGateIssuance(t *testing.T) {
	t.Parallel()
	for name, hint := range map[string]*oidc.MFAEnrollment{
		"no advisory snapshot": nil, "missing version": {}, "future version": {Version: 2, SetupAvailable: true},
		"unenrolled unavailable": {Version: 1}, "unenrolled ready": {Version: 1, SetupAvailable: true},
		"enrolled unavailable": {Version: 1, Enrolled: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			h.admission.Projection.MFA = hint
			h.admission.Projection.Profile["authhub_mfa"] = "untrusted-display"
			response := h.issue(t)
			claims := &sessionTokenClaims{}
			_, _, err := jwt.NewParser().ParseUnverified(response.IDToken, claims)
			require.NoError(t, err)
			if hint == nil || hint.Version != 1 {
				require.Nil(t, claims.MFA)
			} else {
				require.Equal(t, hint, claims.MFA)
			}
		})
	}
}

func TestSessionMFAAdvisoryRequiresProfileScope(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Projection.MFA = &oidc.MFAEnrollment{Version: 1, SetupAvailable: true}
	response, _, _, err := h.service.prepareTokens(t.Context(), h.admission, h.admission.Binding,
		[]string{oidc.ScopeOpenID}, "nonce", h.admission.Binding.SessionID)
	require.NoError(t, err)
	claims := &sessionTokenClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(response.IDToken, claims)
	require.NoError(t, err)
	require.Nil(t, claims.MFA)
}
