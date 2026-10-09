package goauth_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

type resetRecipientPolicy struct {
	subject goauth.SubjectID
	address string
	denied  bool
	lookup  func()
	prepare func(context.Context, goauth.Account, string) (string, error)
}

func (p *resetRecipientPolicy) LookupPasswordResetSubject(context.Context, string) (goauth.SubjectID, error) {
	if p.lookup != nil {
		p.lookup()
	}
	if p.denied {
		return goauth.SubjectID{}, goauth.ErrAccountNotFound
	}
	return p.subject, nil
}

func (p *resetRecipientPolicy) ResolvePasswordResetRecipient(
	_ context.Context, account goauth.Account, requested string,
) (string, error) {
	if p.denied || account.Subject.ID != p.subject || (requested != "" && requested != p.address) {
		return "", goauth.ErrAccountNotFound
	}
	return p.address, nil
}

func resetRecipientFixture(t *testing.T) (*testkit.Fixture, *resetRecipientPolicy, goauth.Account) {
	t.Helper()
	policy := &resetRecipientPolicy{address: "recovery@example.test"}
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.PasswordResetRecipientResolver = policy
		c.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			localIdentityScheme: goauth.IdentifierResolverFunc(func(
				_ context.Context, input goauth.IdentifierInput,
			) (goauth.IdentifierInput, error) {
				return input, nil
			}),
		}
	})
	require.NoError(t, err)
	account, err := fixture.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "RecoveryUser"},
		Password:   testPassword,
	})
	require.NoError(t, err)
	policy.subject = account.Subject.ID
	return fixture, policy, account
}

func recipientResetToken(t *testing.T, fixture *testkit.Fixture) string {
	t.Helper()
	events := fixture.Events.Events()
	require.NotEmpty(t, events)
	notification, err := fixture.Runtime.DecryptNotificationEvent(events[len(events)-1])
	require.NoError(t, err)
	resetURL, err := url.Parse(notification.Data["reset_url"])
	require.NoError(t, err)
	require.Empty(t, resetURL.Query().Get("email"))
	token := resetURL.Query().Get("token")
	require.NotEmpty(t, token)
	return token
}

func TestHostRecipientResetPreservesEmailLessIdentity(t *testing.T) {
	fixture, policy, account := resetRecipientFixture(t)
	var receipt goauth.PasswordResetReceipt
	require.NoError(t, fixture.Runtime.RequestPasswordResetWithReceipt(t.Context(), " RECOVERY@EXAMPLE.TEST ",
		func(_ context.Context, value goauth.PasswordResetReceipt) error {
			receipt = value
			return nil
		}))
	require.Equal(t, account.Subject.ID, receipt.SubjectID)
	require.NotEmpty(t, receipt.Selector)
	events := fixture.Events.Events()
	require.Len(t, events, 1)
	notification, err := fixture.Runtime.DecryptNotificationEvent(events[0])
	require.NoError(t, err)
	require.Equal(t, policy.address, notification.To)
	require.Equal(t, "15m0s", notification.Data["expires"])
	token := recipientResetToken(t, fixture)
	require.NoError(t, fixture.Runtime.ResetPassword(t.Context(), token, "Replacement-Recipient-Passphrase-42"))
	require.ErrorIs(t,
		fixture.Runtime.ResetPassword(t.Context(), token, "Different-Recipient-Passphrase-42"), goauth.ErrResetAlreadyUsed)
	current, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Zero(t, current.Account.PrimaryEmail)
	require.False(t, current.Account.EmailVerified())
	require.Equal(t, account.Subject.SecurityVersion+1, current.Account.Subject.SecurityVersion)
	events = fixture.Events.Events()
	require.Len(t, events, 2)
	success, err := fixture.Runtime.DecryptNotificationEvent(events[1])
	require.NoError(t, err)
	require.Equal(t, "password_reset_success", success.Template)
	require.Equal(t, policy.address, success.To)
}

func TestHostRecipientConsumeRejectionRollsBackPasswordAndToken(t *testing.T) {
	fixture, policy, account := resetRecipientFixture(t)
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), policy.address))
	token := recipientResetToken(t, fixture)
	before, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	policy.denied = true
	require.ErrorIs(t,
		fixture.Runtime.ResetPassword(t.Context(), token, "Replacement-Recipient-Passphrase-42"), goauth.ErrInvalidToken)
	after, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Len(t, fixture.Events.Events(), 1)
	policy.denied = false
	require.NoError(t, fixture.Runtime.ResetPassword(t.Context(), token, "Replacement-Recipient-Passphrase-42"))
}

func TestHostRecipientIssuanceDenialsRemainAccepted(t *testing.T) {
	for _, scenario := range []string{"collision", "wrong address", "inactive", "missing local credential"} {
		t.Run(scenario, func(t *testing.T) {
			fixture, policy, account := resetRecipientFixture(t)
			email := policy.address
			switch scenario {
			case "collision":
				policy.denied = true
			case "wrong address":
				email = otherTestEmail
			case "inactive":
				_, err := fixture.Runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
				require.NoError(t, err)
			case "missing local credential":
				policy.subject = goauth.NewSubjectID()
				_, _, err := fixture.Store.CreateSSOAccount(t.Context(), goauth.SSOAccountRecord{
					Account: goauth.Account{
						Subject: goauth.Subject{ID: policy.subject, Status: goauth.SubjectStatusActive, SecurityVersion: 1},
						PrimaryEmail: goauth.Identifier{
							ID: "sso-recipient", SubjectID: policy.subject,
							Scheme: goauth.IdentifierSchemeEmail, DisplayValue: policy.address, NormalizedValue: policy.address,
						},
					},
					Link: goauth.IdentityLink{SubjectID: policy.subject, Issuer: "https://sso.example.test", ExternalSubject: "sso-recipient"},
				})
				require.NoError(t, err)
			}
			called := false
			require.NoError(t, fixture.Runtime.RequestPasswordResetWithReceipt(t.Context(), email,
				func(context.Context, goauth.PasswordResetReceipt) error {
					called = true
					return nil
				}))
			require.False(t, called)
			require.Empty(t, fixture.Events.Events())
		})
	}
}

func TestHostRecipientReceiptFailureRollsBackIssuance(t *testing.T) {
	fixture, policy, _ := resetRecipientFixture(t)
	rejected := errors.New("reject host receipt")
	err := fixture.Runtime.RequestPasswordResetWithReceipt(t.Context(), policy.address,
		func(context.Context, goauth.PasswordResetReceipt) error { return rejected })
	require.ErrorIs(t, err, rejected)
	require.Empty(t, fixture.Events.Events())
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), policy.address))
	require.NotEmpty(t, recipientResetToken(t, fixture))
}

func TestHostRecipientInvalidationSurvivesAddressRestoration(t *testing.T) {
	fixture, policy, account := resetRecipientFixture(t)
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), policy.address))
	token := recipientResetToken(t, fixture)
	old := policy.address
	require.NoError(t, fixture.Store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		return fixture.Store.InvalidatePasswordResets(ctx, account.Subject.ID, time.Now().UTC())
	}))
	policy.address = "replacement@example.test"
	policy.address = old
	require.ErrorIs(t,
		fixture.Runtime.ResetPassword(t.Context(), token, "Replacement-Recipient-Passphrase-42"), goauth.ErrResetAlreadyUsed)
}

func TestPrimaryEmailDefaultDoesNotAuthorizeHostAlias(t *testing.T) {
	fixture := newFixture(t)
	registerAccount(t, fixture, "primary.recipient@example.test")
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), "unconfigured.alias@example.test"))
	require.Empty(t, fixture.Events.Events())
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), "primary.recipient@example.test"))
	require.Len(t, fixture.Events.Events(), 1)
}

type noSubjectResetStore struct{ goauth.RuntimeStore }

func TestRecipientPolicyRequiresExplicitStoreCapability(t *testing.T) {
	_, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.Store = noSubjectResetStore{RuntimeStore: c.Store}
		c.PasswordResetRecipientResolver = &resetRecipientPolicy{}
	})
	require.ErrorContains(t, err, "subject-bound reset store")
}

type staleRecipientStore struct {
	*testkit.Store
	afterRead func(context.Context, goauth.SubjectID)
}

func (s *staleRecipientStore) GetLocalAccount(ctx context.Context, id goauth.SubjectID) (goauth.LocalAccountRecord, error) {
	record, err := s.Store.GetLocalAccount(ctx, id)
	if err == nil && s.afterRead != nil {
		fn := s.afterRead
		s.afterRead = nil
		fn(ctx, id)
	}
	return record, err
}

func TestRecipientIssuanceRejectsStaleSecuritySnapshot(t *testing.T) {
	policy := &resetRecipientPolicy{address: "snapshot@example.test"}
	var store *staleRecipientStore
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		fixtureStore, ok := c.Store.(*testkit.Store)
		require.True(t, ok)
		store = &staleRecipientStore{Store: fixtureStore}
		c.Store = store
		c.PasswordResetRecipientResolver = policy
	})
	require.NoError(t, err)
	account := registerAccount(t, fixture, policy.address).Account
	policy.subject = account.Subject.ID
	store.afterRead = func(ctx context.Context, id goauth.SubjectID) {
		_, err := store.SetSubjectStatus(ctx, id, goauth.SubjectStatusDisabled, time.Now().UTC())
		require.NoError(t, err)
		_, err = store.SetSubjectStatus(ctx, id, goauth.SubjectStatusActive, time.Now().UTC())
		require.NoError(t, err)
	}
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), policy.address))
	require.Empty(t, fixture.Events.Events())
}

func (p *resetRecipientPolicy) PreparePasswordResetPassword(
	ctx context.Context, account goauth.Account, password string,
) (string, error) {
	if len(password) > 256 {
		return "", goauth.ErrInvalidPassword
	}
	if p.prepare != nil {
		return p.prepare(ctx, account, password)
	}
	return "", nil
}

func TestHostRecipientPasswordPolicyFailureRollsBackConsumption(t *testing.T) {
	fixture, policy, account := resetRecipientFixture(t)
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), policy.address))
	token := recipientResetToken(t, fixture)
	before, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.ErrorIs(t, fixture.Runtime.ResetPassword(t.Context(), token, strings.Repeat("🙂", 65)), goauth.ErrInvalidPassword)
	after, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Len(t, fixture.Events.Events(), 1)
	require.NoError(t, fixture.Runtime.ResetPassword(t.Context(), token, "Replacement-Recipient-Passphrase-42"))
}

func TestHostRecipientPreservesCustomPasswordIssuanceProfile(t *testing.T) {
	fixture, policy, account := resetRecipientFixture(t)
	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{MemoryKiB: 64 * 1024, Iterations: 3})
	require.NoError(t, err)
	policy.prepare = func(_ context.Context, _ goauth.Account, password string) (string, error) {
		return hasher.HashPassword(password)
	}
	require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), policy.address))
	replacement := "Canonical-Recipient-Password-42"
	require.NoError(t, fixture.Runtime.ResetPassword(t.Context(), recipientResetToken(t, fixture), replacement))
	record, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Contains(t, record.PasswordPHC, "m=65536,t=3,p=1")
	require.NoError(t, hasher.VerifyPassword(record.PasswordPHC, replacement))
}
