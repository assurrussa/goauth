package goauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	reauthNextEmail           = "reauth.next@example.test"
	reauthPassword            = "Reauth-Initial-Unique-Passphrase-42" //nolint:gosec // Isolated fixture credential.
	reauthReplacementPassword = "Reauth-Replacement-Passphrase-42"    //nolint:gosec // Isolated fixture credential.
)

func reauthFixture(t *testing.T, options ...testkit.RuntimeOption) (*testkit.Fixture, goauth.Account) {
	t.Helper()
	fixture, err := testkit.NewRuntime(options...)
	require.NoError(t, err)
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "reauth.previous@example.test", Password: reauthPassword,
	})
	require.NoError(t, err)
	return fixture, account
}

func TestEmailChangeRequiresThisSubjectsPassword(t *testing.T) {
	t.Parallel()
	fixture, account := reauthFixture(t)
	const otherPassword = "Reauth-Other-Account-Passphrase-42" //nolint:gosec // Isolated fixture credential.
	_, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "reauth.other@example.test", Password: otherPassword,
	})
	require.NoError(t, err)
	for _, password := range []string{"", wrongTestPassword, otherPassword} {
		err := fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
			SubjectID: account.Subject.ID, CurrentPassword: password, NewEmail: reauthNextEmail,
		})
		require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
		_, err = fixture.Runtime.PendingEmailChange(t.Context(), account.Subject.ID)
		require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
		require.Empty(t, fixture.Events.Events())
	}
}

func TestEmailChangeReauthenticationAndPreviousMailboxNotification(t *testing.T) {
	t.Parallel()
	fixture, account := reauthFixture(t)
	require.NoError(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: reauthPassword, NewEmail: reauthNextEmail,
	}))
	changed, err := fixture.Runtime.ConfirmEmailChange(t.Context(), account.Subject.ID, latestEmailChangeCode(t, fixture))
	require.NoError(t, err)
	require.Equal(t, reauthNextEmail, changed.PrimaryEmail.NormalizedValue)
	var notices int
	for _, event := range fixture.Events.Events() {
		if event.Type != "email_changed" {
			continue
		}
		notice, err := fixture.Runtime.DecryptNotificationEvent(event)
		require.NoError(t, err)
		require.Equal(t, account.PrimaryEmail.DisplayValue, notice.To)
		require.Empty(t, notice.Data, "previous mailbox receives no credential or confirmation code")
		notices++
	}
	require.Equal(t, 1, notices)
}

func TestEmailAndPasswordChangesShareSubjectAttemptBudget(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	fixture, account := reauthFixture(t, func(c *goauth.Config) {
		c.Now = func() time.Time { return now }
		c.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 2}
	})
	_, err := fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: "wrong", NewPassword: reauthReplacementPassword,
	})
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	request := goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: "wrong", NewEmail: reauthNextEmail,
	}
	require.ErrorIs(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), request), goauth.ErrCurrentPasswordInvalid)
	request.CurrentPassword = reauthPassword
	require.ErrorIs(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), request), goauth.ErrAuthenticationRateLimited)
	require.Empty(t, fixture.Events.Events())
	_, err = fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: reauthPassword, NewPassword: reauthReplacementPassword,
	})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	now = now.Add(2 * time.Minute)
	require.NoError(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), request))
}

type reauthSnapshotStore struct {
	goauth.RuntimeStore
	afterRead func()
}

func (s *reauthSnapshotStore) GetLocalAccount(ctx context.Context, id goauth.SubjectID) (goauth.LocalAccountRecord, error) {
	record, err := s.RuntimeStore.GetLocalAccount(ctx, id)
	if err == nil && s.afterRead != nil {
		afterRead := s.afterRead
		s.afterRead = nil
		afterRead()
	}
	return record, err
}

func TestEmailChangeDoesNotUpgradeStalePasswordProof(t *testing.T) {
	t.Parallel()
	var store *reauthSnapshotStore
	fixture, account := reauthFixture(t, func(c *goauth.Config) {
		store = &reauthSnapshotStore{RuntimeStore: c.Store}
		c.Store = store
	})
	store.afterRead = func() {
		_, err := fixture.Runtime.LogoutAll(t.Context(), account.Subject.ID)
		require.NoError(t, err)
	}
	err := fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: reauthPassword, NewEmail: reauthNextEmail,
	})
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	require.Empty(t, fixture.Events.Events())
	_, err = fixture.Runtime.PendingEmailChange(t.Context(), account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}

type reauthFailingSink struct {
	goauth.EncryptedEventSink
	failType string
}

var errReauthDelivery = errors.New("injected reauthentication delivery failure")

func (s *reauthFailingSink) EnqueueEncrypted(ctx context.Context, event goauth.EncryptedEvent) error {
	if event.Type == s.failType {
		return errReauthDelivery
	}
	return s.EncryptedEventSink.EnqueueEncrypted(ctx, event)
}

func TestEmailChangeEnqueueRollbackDoesNotRefundPasswordAttempt(t *testing.T) {
	t.Parallel()
	var sink *reauthFailingSink
	fixture, account := reauthFixture(t, func(c *goauth.Config) {
		c.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
		sink = &reauthFailingSink{EncryptedEventSink: c.EventSink, failType: "email_change"}
		c.EventSink = sink
	})
	request := goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: reauthPassword, NewEmail: reauthNextEmail,
	}
	require.ErrorIs(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), request), errReauthDelivery)
	_, err := fixture.Runtime.PendingEmailChange(t.Context(), account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	require.Empty(t, fixture.Events.Events())
	sink.failType = ""
	require.ErrorIs(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), request), goauth.ErrAuthenticationRateLimited)
}

func TestPreviousMailboxNotificationFailureRollsBackConfirmation(t *testing.T) {
	t.Parallel()
	var sink *reauthFailingSink
	fixture, account := reauthFixture(t, func(c *goauth.Config) {
		sink = &reauthFailingSink{EncryptedEventSink: c.EventSink, failType: "email_changed"}
		c.EventSink = sink
	})
	require.NoError(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: reauthPassword, NewEmail: reauthNextEmail,
	}))
	code := latestEmailChangeCode(t, fixture)
	_, err := fixture.Runtime.ConfirmEmailChange(t.Context(), account.Subject.ID, code)
	require.ErrorIs(t, err, errReauthDelivery)
	unchanged, err := fixture.Runtime.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, account.PrimaryEmail.NormalizedValue, unchanged.PrimaryEmail.NormalizedValue)
	require.Equal(t, account.Subject.SecurityVersion, unchanged.Subject.SecurityVersion)
	sink.failType = ""
	_, err = fixture.Runtime.ConfirmEmailChange(t.Context(), account.Subject.ID, code)
	require.NoError(t, err, "failed notification enqueue must not consume the confirmation code")
}

func TestEmailChangeWithPasswordRejectsSSOOnlyAccounts(t *testing.T) {
	t.Parallel()
	fixture, _ := reauthFixture(t)
	account, err := fixture.Runtime.ResolveExternalIdentity(t.Context(), goauth.ExternalIdentity{
		Issuer: "https://reauth.example.test", Subject: ssoOnlySubject, Email: "reauth.sso@example.test", EmailVerified: true,
	})
	require.NoError(t, err)
	err = fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
		SubjectID: account.Subject.ID, CurrentPassword: reauthPassword, NewEmail: reauthNextEmail,
	})
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	require.Empty(t, fixture.Events.Events())
}
