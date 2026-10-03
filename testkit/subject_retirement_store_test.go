//nolint:testpackage // Exercises retained reservations, deleted credentials and terminal fixture storage directly.
package testkit

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func retirementStoreFixture(t *testing.T) (*Store, goauth.RetireLocalIdentityStoreRequest) {
	t.Helper()
	store := NewStore()
	id := goauth.NewSubjectID()
	now := time.Now().UTC()
	primary := goauth.Identifier{
		ID: "retirement-primary", SubjectID: id, Scheme: "retirement_test", DisplayValue: "RetiredLogin",
		NormalizedValue: "RetiredLogin", CreatedAt: now, UpdatedAt: now,
	}
	_, err := store.CreateLocalIdentity(t.Context(), goauth.LocalIdentityRecord{
		LocalAccountRecord: goauth.LocalAccountRecord{
			Account: goauth.Account{Subject: goauth.Subject{
				ID: id, Status: goauth.SubjectStatusActive, SecurityVersion: 1, CreatedAt: now, UpdatedAt: now,
			}},
			PasswordPHC: "synthetic-retirement-phc", PasswordInputPolicy: goauth.PasswordInputPolicyUnicode,
		}, Identifier: primary,
	})
	require.NoError(t, err)
	return store, goauth.RetireLocalIdentityStoreRequest{
		SubjectID: id, Scheme: primary.Scheme,
		ExpectedNormalizedValue: primary.NormalizedValue, ExpectedSecurityVersion: 1, Now: now,
	}
}

func TestSubjectRetirementStoreBoundsMissingCredentialAndOverflow(t *testing.T) {
	for _, field := range []string{
		"retire subject", "retire scheme", "retire email-scheme", "retire version", "retire timestamp",
		"retire expected", "retire wrong-login", "retire overflow", "retire credential", "retire primary",
	} {
		t.Run(field, func(t *testing.T) {
			store, request := retirementStoreFixture(t)
			id := request.SubjectID
			switch field {
			case "retire subject":
				request.SubjectID = goauth.NilSubjectID
			case "retire scheme":
				request.Scheme = ""
			case "retire email-scheme":
				request.Scheme = goauth.IdentifierSchemeEmail
			case "retire version":
				request.ExpectedSecurityVersion = 0
			case "retire timestamp":
				request.Now = time.Time{}
			case "retire expected":
				request.ExpectedNormalizedValue = "bad\x00login"
			case "retire wrong-login":
				request.ExpectedNormalizedValue = "unowned"
			case "retire overflow":
				account := store.accounts[id.String()]
				account.Subject.SecurityVersion = math.MaxInt64
				store.accounts[id.String()] = account
				request.ExpectedSecurityVersion = math.MaxInt64
			case "retire credential":
				delete(store.passwords, id.String())
			case "retire primary":
				delete(store.localIdentifiers, localIdentifierKey(id, request.Scheme))
			}
			before := store.snapshot()
			view, err := store.RetireLocalIdentity(t.Context(), request)
			require.Error(t, err)
			require.Zero(t, view)
			require.Equal(t, before.accounts, store.accounts)
			require.Equal(t, before.identifiers, store.identifiers)
			require.Equal(t, before.passwords, store.passwords)
			require.Empty(t, store.retired)
		})
	}
}

func TestSubjectRetirementStoreRetainsAliasesAndRejectsSSOOverwrite(t *testing.T) {
	store, request := retirementStoreFixture(t)
	id := request.SubjectID
	aliasKey := identifierKey(request.Scheme, "RetainedAlias")
	store.identifiers[aliasKey] = id.String()
	secondary := goauth.Identifier{
		ID: "second-primary", SubjectID: id, Scheme: "another", DisplayValue: "Other", NormalizedValue: "Other",
	}
	store.localIdentifiers[localIdentifierKey(id, secondary.Scheme)] = secondary
	store.identifiers[identifierKey(secondary.Scheme, secondary.NormalizedValue)] = id.String()
	link := goauth.IdentityLink{
		ID: "kept-link", SubjectID: id, Issuer: "https://fixture.example.test", ExternalSubject: "kept-subject",
	}
	_, err := store.LinkIdentity(t.Context(), link)
	require.NoError(t, err)
	require.NoError(t, store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, err := store.RetireLocalIdentity(ctx, request)
		return err
	}))
	require.Equal(t, id.String(), store.identifiers[aliasKey])
	require.Equal(t, secondary, store.localIdentifiers[localIdentifierKey(id, secondary.Scheme)])
	require.Equal(t, link, store.links[identityKey(link.Issuer, link.ExternalSubject)])
	require.NotContains(t, store.passwords, id.String())
	require.NotContains(t, store.passwordPolicies, id.String())
	freshID := goauth.NewSubjectID()
	fresh := goauth.Account{
		Subject: goauth.Subject{ID: freshID, Status: goauth.SubjectStatusActive, SecurityVersion: 1},
		PrimaryEmail: goauth.Identifier{
			ID: "fresh-email", SubjectID: freshID, Scheme: goauth.IdentifierSchemeEmail,
			NormalizedValue: "fresh-retirement@example.test",
		},
	}
	_, _, err = store.CreateSSOAccount(t.Context(), goauth.SSOAccountRecord{
		Account: fresh,
		Link:    goauth.IdentityLink{ID: "misbound-link", SubjectID: id, Issuer: link.Issuer, ExternalSubject: "misbound"},
	})
	require.Error(t, err)
	require.NotContains(t, store.accounts, freshID.String())
	require.NotContains(t, store.links, identityKey(link.Issuer, "misbound"))
	before, err := store.GetSubjectLifecycle(t.Context(), id)
	require.NoError(t, err)
	attempted := before.Account
	attempted.Subject.Status = goauth.SubjectStatusActive
	attempted.PrimaryEmail = goauth.Identifier{
		ID: "replacement-email", SubjectID: id, Scheme: goauth.IdentifierSchemeEmail,
		NormalizedValue: "retirement-replacement@example.test",
	}
	_, _, err = store.CreateSSOAccount(t.Context(), goauth.SSOAccountRecord{Account: attempted, Link: goauth.IdentityLink{
		ID: "new-link", SubjectID: id, Issuer: link.Issuer, ExternalSubject: "other-subject",
	}})
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	after, err := store.GetSubjectLifecycle(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestSubjectRetirementStoreKeepsEmailReservationImmutable(t *testing.T) {
	store, request := retirementStoreFixture(t)
	id, now := request.SubjectID, request.Now
	account := store.accounts[id.String()]
	account.PrimaryEmail = goauth.Identifier{
		ID: "retirement-email", SubjectID: id, Scheme: goauth.IdentifierSchemeEmail,
		DisplayValue: "reserved-retirement@example.test", NormalizedValue: "reserved-retirement@example.test",
		CreatedAt: now, UpdatedAt: now,
	}
	store.accounts[id.String()] = account
	emailKey := identifierKey(goauth.IdentifierSchemeEmail, account.PrimaryEmail.NormalizedValue)
	store.identifiers[emailKey] = id.String()
	_, err := store.RetireLocalIdentity(t.Context(), request)
	require.NoError(t, err)
	before, err := store.GetSubjectLifecycle(t.Context(), id)
	require.NoError(t, err)
	challenge := goauth.EmailChallengeRecord{
		SubjectID: id, IdentifierID: account.PrimaryEmail.ID, Purpose: goauth.EmailChallengePurposeVerification,
	}
	// Even legacy direct callers omitting an expected snapshot cannot issue state
	// that changes the terminal subject's retained email or verification.
	issued, err := store.IssueEmailChallenge(t.Context(), challenge, goauth.EmailChallengeLimits{})
	require.ErrorIs(t, err, goauth.ErrSubjectRetired)
	require.Zero(t, issued)
	verified, err := store.VerifyEmailChallenge(t.Context(), goauth.EmailChallengeVerifyRequest{
		SubjectID: id, Purpose: goauth.EmailChallengePurposeVerification, Now: now,
	})
	require.ErrorIs(t, err, goauth.ErrSubjectRetired)
	require.Zero(t, verified)
	change, err := store.IssueEmailChange(t.Context(), goauth.EmailChangeRecord{
		SubjectID: id, NewDisplayValue: "released@example.test", NewNormalizedValue: "released@example.test",
	}, goauth.EmailChallengeLimits{})
	require.ErrorIs(t, err, goauth.ErrSubjectRetired)
	require.Zero(t, change)
	changed, err := store.VerifyEmailChange(t.Context(), goauth.EmailChangeVerifyRequest{SubjectID: id, Now: now})
	require.ErrorIs(t, err, goauth.ErrSubjectRetired)
	require.Zero(t, changed)
	after, err := store.GetSubjectLifecycle(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Equal(t, id.String(), store.identifiers[emailKey])
	require.Empty(t, store.challenges)
	require.Empty(t, store.emailChanges)
	require.Empty(t, store.rateEvents)
}
