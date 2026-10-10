package goauth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestDisabledDeliveryAllowsPasswordAndRejectsRecoveryBeforeAdmission(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.NotificationDelivery = goauth.NotificationDeliveryDisabled
		c.EventSink = nil
		c.URLBuilder = nil
		c.OutboxAEADKeys = goauth.KeyRing{}
	})
	require.NoError(t, err)
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: testEmail, Password: testPassword,
	})
	require.NoError(t, err)
	// Repeated disabled email commands must not consume password-guessing budget.
	for range 15 {
		require.ErrorIs(t, fixture.Runtime.RequestPasswordReset(t.Context(), testEmail), goauth.ErrNotificationDeliveryDisabled)
		require.ErrorIs(t,
			fixture.Runtime.ResetPassword(t.Context(), "old-token", "new-password"),
			goauth.ErrNotificationDeliveryDisabled)
		require.ErrorIs(t, fixture.Runtime.SendEmailChallenge(
			t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification), goauth.ErrNotificationDeliveryDisabled)
		require.ErrorIs(t, fixture.Runtime.RequestEmailChangeWithPassword(t.Context(), goauth.PasswordEmailChangeRequest{
			SubjectID: account.Subject.ID, CurrentPassword: "disabled-command-password", NewEmail: otherTestEmail,
		}), goauth.ErrNotificationDeliveryDisabled)
	}
	_, err = fixture.Runtime.Login(t.Context(), loginRequest(testEmail, testPassword, goauth.RealmUser))
	require.NoError(t, err)
	_, err = fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: testPassword, NewPassword: "New-Unique-Passphrase-2",
	})
	require.NoError(t, err)
	require.Empty(t, fixture.Events.Events())
	_, err = fixture.Runtime.Login(t.Context(), loginRequest(testEmail, "New-Unique-Passphrase-2", goauth.RealmUser))
	require.NoError(t, err)
}

func TestDisabledDeliveryRetainsMandatoryAudit(t *testing.T) {
	_, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.NotificationDelivery = goauth.NotificationDeliveryDisabled
		c.EventSink = nil
		c.AuditSink = nil
	})
	require.ErrorContains(t, err, "transactional audit sink is required")
}
