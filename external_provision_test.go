package goauth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/assurrussa/goauth"
)

func TestProvisionExternalIdentityNeverLinksExistingEmail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	existing := registerAccount(t, f, "strict-existing@example.test")
	verifyEmail(t, f, existing.Account.Subject.ID)
	_, err := f.Runtime.ProvisionExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer: testOIDCIssuer, Subject: "strict-new-subject",
		Email: "STRICT-EXISTING@example.test", EmailVerified: true,
	})
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink)
	_, _, err = f.Store.ResolveIdentityLink(context.Background(), testOIDCIssuer, "strict-new-subject")
	require.ErrorIs(t, err, goauth.ErrIdentityLinkNotFound)
}

func TestProvisionExternalIdentityCreatesOnlySSOAccount(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()
	identity := goauth.ExternalIdentity{Issuer: testOIDCIssuer, Subject: "strict-new",
		Email: "strict-new@example.test", EmailVerified: true}
	first, err := f.Runtime.ProvisionExternalIdentity(ctx, identity)
	require.NoError(t, err)
	require.True(t, first.EmailVerified())
	_, err = f.Store.FindLocalAccount(ctx, goauth.IdentifierInput{
		Scheme: goauth.IdentifierSchemeEmail, Value: identity.Email,
	})
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	repeated, err := f.Runtime.ProvisionExternalIdentity(ctx, goauth.ExternalIdentity{
		Issuer: identity.Issuer, Subject: identity.Subject,
	})
	require.NoError(t, err)
	require.Equal(t, first.Subject.ID, repeated.Subject.ID)
	_, _, err = f.Store.ResolveIdentityLink(ctx, identity.Issuer+"/other", identity.Subject)
	require.ErrorIs(t, err, goauth.ErrIdentityLinkNotFound)
}

func TestProvisionExternalIdentityMissingIdentityFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for _, identity := range []goauth.ExternalIdentity{
		{}, {Issuer: testOIDCIssuer}, {Subject: "no-issuer"},
		{Issuer: testOIDCIssuer, Subject: "no-email"},
	} {
		_, err := f.Runtime.ProvisionExternalIdentity(context.Background(), identity)
		require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
	}
}
