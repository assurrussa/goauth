//nolint:testpackage // Exercises the provider's persisted authorization-code boundary.
package provider

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
)

const reviewCodeVerifier = "review-code-verifier-with-sufficient-test-entropy"

func issueReviewCode(t *testing.T, h *oidcTestHarness) string {
	t.Helper()
	result, err := h.service.issueAuthorizationCode(t.Context(), authorizationCodeInput{
		ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0],
		Scopes:        []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
		CodeChallenge: codeChallengeFor(reviewCodeVerifier), CodeChallengeMethod: codeChallengeMethodS256,
	}, oidc.AuthenticatedSubject{Account: h.subject, AuthenticatedAt: h.now})
	require.NoError(t, err)
	redirect, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	code := redirect.Query().Get("code")
	require.NotEmpty(t, code)
	require.Equal(t, h.subject.Subject.SecurityVersion, h.codes.items[code].SecurityVersion)
	return code
}

func exchangeReviewCode(h *oidcTestHarness, code string) (*oidc.TokenResponse, error) {
	return h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: code, ClientID: h.client.ID,
		RedirectURI: h.client.RedirectURIs[0], CodeVerifier: reviewCodeVerifier,
	})
}

func TestReviewAuthorizationCodeBindsSecurityVersion(t *testing.T) {
	for _, change := range []string{"current", "security-version", "disabled", "versionless", "wrong-subject"} {
		t.Run(change, func(t *testing.T) {
			h := newOIDCTestHarness(t)
			code := issueReviewCode(t, h)
			current := h.subject
			switch change {
			case "security-version":
				// This is the canonical transition made by password reset/logout-all.
				current.Subject.SecurityVersion++
			case "disabled":
				current.Subject.Status = goauth.SubjectStatusDisabled
			case "versionless":
				record := h.codes.items[code]
				record.SecurityVersion = 0
				h.codes.items[code] = record
			case "wrong-subject":
				current.Subject.ID = goauth.NewSubjectID()
			}
			h.service.claims = &memoryClaimsResolver{items: map[string]goauth.Account{
				h.subject.Subject.ID.String(): current,
			}}
			response, err := exchangeReviewCode(h, code)
			if change == "current" {
				require.NoError(t, err)
				require.NotEmpty(t, response.AccessToken)
				require.NotEmpty(t, response.RefreshToken)
			} else {
				requireOAuthError(t, err, "invalid_grant")
				require.Nil(t, response)
				require.Empty(t, h.refreshTokens.items)
			}
			_, err = h.codes.Consume(t.Context(), code)
			require.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)
		})
	}
}

func TestReviewStaleAuthenticationCannotIssueAuthorizationCode(t *testing.T) {
	h := newOIDCTestHarness(t)
	current := h.subject
	current.Subject.SecurityVersion++
	h.service.claims = &memoryClaimsResolver{items: map[string]goauth.Account{
		h.subject.Subject.ID.String(): current,
	}}
	result, err := h.service.issueAuthorizationCode(t.Context(), authorizationCodeInput{
		ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0],
		Scopes:        []string{oidc.ScopeOpenID},
		CodeChallenge: codeChallengeFor(reviewCodeVerifier), CodeChallengeMethod: codeChallengeMethodS256,
	}, oidc.AuthenticatedSubject{Account: h.subject, AuthenticatedAt: h.now})
	requireOAuthError(t, err, "invalid_grant")
	require.Nil(t, result)
	require.Empty(t, h.codes.items)
}

type reviewClaimsResolver func(context.Context, string) (goauth.Account, error)

func (f reviewClaimsResolver) Resolve(ctx context.Context, subject string) (goauth.Account, error) {
	return f(ctx, subject)
}

func TestReviewAuthorizationCodeExpiresDuringSubjectResolution(t *testing.T) {
	h := newOIDCTestHarness(t)
	code := issueReviewCode(t, h)
	now := h.now
	h.service.now = func() time.Time { return now }
	h.service.claims = reviewClaimsResolver(func(context.Context, string) (goauth.Account, error) {
		now = h.codesExpiryForReview()
		return h.subject, nil
	})
	response, err := exchangeReviewCode(h, code)
	requireOAuthError(t, err, "invalid_grant")
	require.Nil(t, response)
	require.Empty(t, h.refreshTokens.items)
}

func (h *oidcTestHarness) codesExpiryForReview() time.Time {
	return h.now.Add(h.service.codeTTL)
}
