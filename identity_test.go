package goauth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestExternalIdentityNeverAutoLinksUnverifiedEmail(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "existing.identity@example.test")

	_, err := fixture.Runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        testOIDCIssuer,
		Subject:       "external-1",
		Email:         "existing.identity@example.test",
		EmailVerified: true,
	})
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink, "the local email is still unverified")

	verifyEmail(t, fixture, registered.Account.Subject.ID)
	_, err = fixture.Runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        testOIDCIssuer,
		Subject:       "external-2",
		Email:         "existing.identity@example.test",
		EmailVerified: false,
	})
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink, "the IdP email is unverified")

	linked, err := fixture.Runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        testOIDCIssuer,
		Subject:       "external-verified",
		Email:         "EXISTING.IDENTITY@example.test",
		EmailVerified: true,
	})
	require.NoError(t, err)
	require.Equal(t, registered.Account.Subject.ID, linked.Subject.ID)
}

func TestSSOOnlyAccountHasNoLocalPassword(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	created, err := fixture.Runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        testOIDCIssuer + "/",
		Subject:       "sso-only",
		Email:         ssoOnlyEmail,
		EmailVerified: true,
		Profile:       goauth.BasicProfile{DisplayName: "SSO Only"},
	})
	require.NoError(t, err)
	require.True(t, created.EmailVerified())

	_, err = fixture.Store.FindLocalAccount(context.Background(), goauth.IdentifierInput{
		Scheme: goauth.IdentifierSchemeEmail,
		Value:  ssoOnlyEmail,
	})
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	resolved, err := fixture.Runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        testOIDCIssuer,
		Subject:       "sso-only",
		Email:         ssoOnlyEmail,
		EmailVerified: true,
	})
	require.NoError(t, err)
	require.Equal(t, created.Subject.ID, resolved.Subject.ID)
}

func TestExplicitLinkRequiresAuthenticatedSession(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "explicit.link@example.test")
	external := goauth.ExternalIdentity{
		Issuer:  testOIDCIssuer,
		Subject: "explicit-link",
		Email:   "different.external@example.test",
	}
	_, err := fixture.Runtime.LinkExternalIdentity(context.Background(), goauth.AuthContext{}, external)
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink)

	verifyEmail(t, fixture, registered.Account.Subject.ID)
	loginResult, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("explicit.link@example.test", testPassword, goauth.RealmUser),
	)
	require.NoError(t, err)
	auth, err := fixture.Runtime.VerifyAccessToken(context.Background(), loginResult.Tokens.AccessToken, true)
	require.NoError(t, err)
	link, err := fixture.Runtime.LinkExternalIdentity(context.Background(), auth, external)
	require.NoError(t, err)
	require.Equal(t, registered.Account.Subject.ID, link.SubjectID)
}

func verifyEmail(t *testing.T, fixture *testkit.Fixture, subjectID goauth.SubjectID) {
	t.Helper()
	require.NoError(t, fixture.Runtime.SendEmailChallenge(
		context.Background(),
		subjectID,
		goauth.EmailChallengePurposeVerification,
	))
	_, err := fixture.Runtime.VerifyEmailChallenge(
		context.Background(),
		subjectID,
		goauth.EmailChallengePurposeVerification,
		latestChallengeCode(t, fixture),
	)
	require.NoError(t, err)
}
