//nolint:testpackage // Uses provider code persistence and a real supported Runtime lifecycle transition.
package provider

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestSubjectRetirementMakesPreviouslyIssuedCodeSequentiallyUnusable(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			"retirement_code": goauth.IdentifierResolverFunc(func(
				_ context.Context, in goauth.IdentifierInput,
			) (goauth.IdentifierInput, error) {
				return in, nil
			}),
		}
	})
	require.NoError(t, err)
	login := goauth.IdentifierInput{Scheme: "retirement_code", Value: "CodeOwner"}
	original, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: login, Password: "Retirement-Code-Synthetic-Passphrase-42",
	})
	require.NoError(t, err)
	harness := newOIDCTestHarness(t)
	harness.subject = original
	harness.service.claims = reviewClaimsResolver(func(ctx context.Context, id string) (goauth.Account, error) {
		subject, err := goauth.ParseSubjectID(id)
		if err != nil {
			return goauth.Account{}, err
		}
		return fixture.Runtime.GetAccount(ctx, subject)
	})
	code := issueReviewCode(t, harness)
	_, err = fixture.Runtime.RetireLocalIdentity(t.Context(), goauth.RetireLocalIdentityRequest{
		SubjectID: original.Subject.ID, ExpectedIdentifier: login, ExpectedSecurityVersion: original.Subject.SecurityVersion,
	})
	require.NoError(t, err)
	replacement, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: login, Password: "Retirement-Code-Synthetic-Passphrase-42",
	})
	require.NoError(t, err)
	require.NotEqual(t, original.Subject.ID, replacement.Subject.ID)
	response, err := exchangeReviewCode(harness, code)
	requireOAuthError(t, err, "invalid_grant")
	require.Nil(t, response)
	require.Empty(t, harness.refreshTokens.items)
	// This is a sequential stale-code test. Provider final-write races remain a
	// separate capability and must not be inferred from this lifecycle fence.
}
