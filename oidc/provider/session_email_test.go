//nolint:testpackage // Checks signed claims and the private typed projection boundary.
package provider

import (
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const sessionVerifiedAddress = "verified@example.test"

func TestSessionHostVerifiedEmailSignedAndScoped(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Projection.Email = &oidc.VerifiedEmail{Address: sessionVerifiedAddress}
	// Neither the unrelated primary email nor display metadata supplies this claim.
	h.admission.Projection.Profile[oidc.ScopeEmail] = "untrusted@example.test"
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
	require.Equal(t, sessionVerifiedAddress, claims.Email)
	require.NotNil(t, claims.EmailVerified)
	require.True(t, *claims.EmailVerified)
	access, err := h.service.parseSessionAccessToken(t.Context(), response.AccessToken)
	require.NoError(t, err)
	require.Empty(t, access.Email, "email is not access-token authorization")
	require.Nil(t, access.EmailVerified)
	info, err := h.service.UserInfo(t.Context(), response.AccessToken)
	require.NoError(t, err)
	require.Equal(t, sessionVerifiedAddress, info.Email)
	require.NotNil(t, info.EmailVerified)
	require.True(t, *info.EmailVerified)
	info = h.service.userInfo(h.admission, []string{oidc.ScopeOpenID, oidc.ScopeProfile})
	require.Empty(t, info.Email)
	require.Nil(t, info.EmailVerified)
}

func TestSessionHostVerifiedEmailRefreshUsesCurrentSnapshot(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Projection.Email = &oidc.VerifiedEmail{Address: sessionVerifiedAddress}
	first := h.issue(t)
	old := &sessionTokenClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(first.IDToken, old)
	require.NoError(t, err)
	h.admission.Projection.Email.Address = "changed@example.test"
	refreshed, err := h.service.ExchangeToken(t.Context(), h.refreshRequest(first.RefreshToken))
	require.NoError(t, err)
	current := &sessionTokenClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(refreshed.IDToken, current)
	require.NoError(t, err)
	require.Equal(t, "changed@example.test", current.Email)
	require.Equal(t, sessionVerifiedAddress, old.Email)
	require.Equal(t, old.Subject, current.Subject)
	require.Equal(t, old.SessionID, current.SessionID)
	require.Equal(t, old.ClientID, current.ClientID)
	require.Equal(t, old.ProjectID, current.ProjectID)
	// A mandatory-email host denies admission when ownership is no longer valid.
	h.admission.Allowed = false
	denied, err := h.service.ExchangeToken(t.Context(), h.refreshRequest(refreshed.RefreshToken))
	require.Error(t, err)
	require.Nil(t, denied)
	_, err = h.service.UserInfo(t.Context(), refreshed.AccessToken)
	require.Error(t, err)
}

func TestSessionHostVerifiedEmailOptionalAndMalformed(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	legacy := h.service.base.buildUserInfo(h.admission.Account, []string{oidc.ScopeOpenID, oidc.ScopeEmail})
	current := h.service.userInfo(h.admission, []string{oidc.ScopeOpenID, oidc.ScopeEmail})
	require.Equal(t, legacy.Email, current.Email)
	require.Equal(t, legacy.EmailVerified, current.EmailVerified)
	require.True(t, validVerifiedEmail(nil))
	for name, address := range map[string]string{
		"empty": "", "uppercase": "User@example.test", "space": " user@example.test",
		"display": "User <user@example.test>", "newline": "user@example.test\n",
		"invalid": "not-an-address", "long": strings.Repeat("a", 255),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newSessionFixture(t)
			f.admission.Projection.Email = &oidc.VerifiedEmail{Address: address}
			require.False(t, validProjection(f.admission.Projection))
			response, _, _, err := f.service.prepareTokens(t.Context(), f.admission, f.admission.Binding,
				[]string{oidc.ScopeOpenID, oidc.ScopeEmail}, "nonce", f.admission.Binding.SessionID)
			require.Error(t, err)
			require.Nil(t, response)
		})
	}
}
