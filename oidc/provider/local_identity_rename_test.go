//nolint:testpackage // Reuses the provider's persisted authorization-code harness.
package provider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const renameCodeScheme goauth.IdentifierScheme = "custom"

// This proves only sequential stale-code rejection, not final-write race safety.
func TestLocalIdentityRenameDeniesAlreadyIssuedCode(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			renameCodeScheme: goauth.IdentifierResolverFunc(func(
				_ context.Context, input goauth.IdentifierInput,
			) (goauth.IdentifierInput, error) {
				return input, nil
			}),
		}
	})
	require.NoError(t, err)
	account, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: renameCodeScheme, Value: "Before"}, Password: "Synthetic-Rename-Code-Passphrase-42",
	})
	require.NoError(t, err)
	h := newOIDCTestHarness(t)
	h.subject = account
	h.service.claims = reviewClaimsResolver(func(ctx context.Context, subject string) (goauth.Account, error) {
		id, err := goauth.ParseSubjectID(subject)
		if err != nil {
			return goauth.Account{}, err
		}
		return fixture.Runtime.GetAccount(ctx, id)
	})
	code := issueReviewCode(t, h)
	_, err = fixture.Runtime.RenameLocalIdentity(t.Context(), goauth.RenameLocalIdentityRequest{
		SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
		ExpectedIdentifier: goauth.IdentifierInput{Scheme: renameCodeScheme, Value: "Before"},
		NewIdentifier:      goauth.IdentifierInput{Scheme: renameCodeScheme, Value: "After"},
	})
	require.NoError(t, err)
	response, err := exchangeReviewCode(h, code)
	requireOAuthError(t, err, "invalid_grant")
	require.Nil(t, response)
	require.Empty(t, h.refreshTokens.items)
}
