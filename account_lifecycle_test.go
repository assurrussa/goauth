package goauth_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestTrustedProvisioningCreatesVerifiedAdminEligibleAccount(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(context.Background(), goauth.RegisterRequest{
		Email:    "Trusted.Admin@Example.Test",
		Password: testPassword,
		Profile:  goauth.BasicProfile{DisplayName: "Trusted Admin"},
	})
	require.NoError(t, err)
	require.True(t, account.EmailVerified())

	verified, err := fixture.Runtime.VerifyCredential(context.Background(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "trusted.admin@example.test"},
		Password:   testPassword,
	})
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, verified.Subject.ID)

	login, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("TRUSTED.ADMIN@EXAMPLE.TEST", testPassword, goauth.RealmAdmin),
	)
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeAuthenticated, login.Tokens.Session.Scope)
}

func TestConcurrentPasswordChangeAllowsOneCASAndRevokesSessions(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "password.change@example.test")

	passwords := []string{"Password-Change-Winner-A1", "Password-Change-Winner-B2"}
	results := make([]error, len(passwords))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, password := range passwords {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, results[index] = fixture.Runtime.ChangePassword(context.Background(), goauth.ChangePasswordRequest{
				SubjectID:       registered.Account.Subject.ID,
				CurrentPassword: testPassword,
				NewPassword:     password,
			})
		}()
	}
	close(start)
	wait.Wait()

	var success int
	var winningPassword string
	for index, err := range results {
		if err == nil {
			success++
			winningPassword = passwords[index]
			continue
		}
		require.True(t,
			errors.Is(err, goauth.ErrPasswordChangeConflict) || errors.Is(err, goauth.ErrCurrentPasswordInvalid),
			"unexpected concurrent password change result: %v", err,
		)
	}
	require.Equal(t, 1, success)
	_, err := fixture.Runtime.VerifyAccessToken(context.Background(), registered.Tokens.AccessToken, true)
	require.Error(t, err)
	_, err = fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	_, err = fixture.Runtime.Login(
		context.Background(),
		loginRequest("password.change@example.test", winningPassword, goauth.RealmUser),
	)
	require.NoError(t, err)
}

func TestLogoutAndLogoutAllRevokeCanonicalSessions(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "logout@example.test")
	second, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("logout@example.test", testPassword, goauth.RealmUser),
	)
	require.NoError(t, err)

	require.NoError(t, fixture.Runtime.Logout(
		context.Background(),
		registered.Account.Subject.ID,
		registered.Tokens.Session.ID,
	))
	_, err = fixture.Runtime.VerifyAccessToken(context.Background(), registered.Tokens.AccessToken, true)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)

	revoked, err := fixture.Runtime.LogoutAll(context.Background(), registered.Account.Subject.ID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, revoked, int64(1))
	_, err = fixture.Runtime.VerifyAccessToken(context.Background(), second.Tokens.AccessToken, true)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

func TestEmailChangePersistsAttemptsThenAtomicallyChangesVerifiedIdentifier(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "email.before@example.test")
	verifyEmail(t, fixture, registered.Account.Subject.ID)
	login, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("email.before@example.test", testPassword, goauth.RealmUser),
	)
	require.NoError(t, err)

	require.NoError(t, fixture.Runtime.RequestEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		"Email.After@Example.Test",
	))
	pending, err := fixture.Runtime.PendingEmailChange(context.Background(), registered.Account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, "Email.After@Example.Test", pending.NewDisplayValue)
	code := latestEmailChangeCode(t, fixture)
	_, err = fixture.Runtime.ConfirmEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		differentCode(code),
	)
	require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	pending, err = fixture.Runtime.PendingEmailChange(context.Background(), registered.Account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, 1, pending.Attempts)

	changed, err := fixture.Runtime.ConfirmEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		code,
	)
	require.NoError(t, err)
	require.Equal(t, "email.after@example.test", changed.PrimaryEmail.NormalizedValue)
	require.True(t, changed.EmailVerified())
	_, err = fixture.Runtime.PendingEmailChange(context.Background(), registered.Account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	_, err = fixture.Runtime.VerifyAccessToken(context.Background(), login.Tokens.AccessToken, true)
	require.Error(t, err)
	_, err = fixture.Runtime.Login(
		context.Background(),
		loginRequest("EMAIL.AFTER@EXAMPLE.TEST", testPassword, goauth.RealmUser),
	)
	require.NoError(t, err)
	_, err = fixture.Runtime.Login(
		context.Background(),
		loginRequest("email.before@example.test", testPassword, goauth.RealmUser),
	)
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
}

func TestUpdateBasicProfileKeepsIdentityModelSeparate(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "profile@example.test")
	updated, err := fixture.Runtime.UpdateBasicProfile(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.BasicProfile{Username: "security", GivenName: "Sec", FamilyName: "Urity"},
	)
	require.NoError(t, err)
	require.Equal(t, "security", updated.Profile.Username)
	require.Equal(t, registered.Account.Subject.ID, updated.Subject.ID)
	require.Equal(t, "profile@example.test", updated.PrimaryEmail.NormalizedValue)
}

func latestEmailChangeCode(t *testing.T, fixture *testkit.Fixture) string {
	t.Helper()
	events := fixture.Events.Events()
	for index := len(events) - 1; index >= 0; index-- {
		if events[index].Type != "email_change" {
			continue
		}
		notification, err := fixture.Runtime.DecryptNotificationEvent(events[index])
		require.NoError(t, err)
		code := notification.Data["code"]
		require.Len(t, code, 6)
		require.False(t, bytes.Contains(events[index].Envelope.Ciphertext, []byte(code)))

		return code
	}
	t.Fatal("email_change notification was not emitted")

	return ""
}
