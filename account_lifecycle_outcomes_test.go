package goauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestAccountLookupAndCredentialOutcomeMapping(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "lookup@example.test")

	account, err := fixture.Runtime.GetAccount(context.Background(), registered.Account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, registered.Account.Subject.ID, account.Subject.ID)
	account, err = fixture.Runtime.FindAccount(context.Background(), goauth.IdentifierInput{
		Scheme: goauth.IdentifierSchemeEmail,
		Value:  " LOOKUP@EXAMPLE.TEST ",
	})
	require.NoError(t, err)
	require.Equal(t, registered.Account.Subject.ID, account.Subject.ID)
	_, err = fixture.Runtime.GetAccount(context.Background(), goauth.NilSubjectID)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = fixture.Runtime.GetAccount(context.Background(), goauth.NewSubjectID())
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = fixture.Runtime.FindAccount(context.Background(), goauth.IdentifierInput{Value: "missing@example.test"})
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = fixture.Runtime.FindAccount(context.Background(), goauth.IdentifierInput{Value: invalidTestEmail})
	require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)

	_, err = fixture.Runtime.VerifyCredential(context.Background(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Value: "lookup@example.test"},
		Password:   wrongTestPassword,
	})
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	_, err = fixture.Runtime.VerifyCredential(context.Background(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Value: "missing@example.test"},
		Password:   testPassword,
	})
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	_, err = fixture.Runtime.VerifyCredential(context.Background(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Value: invalidTestEmail},
		Password:   testPassword,
	})
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
}

func TestPasswordProfileAndLogoutTypedOutcomes(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "lifecycle.outcomes@example.test")

	_, err := fixture.Runtime.UpdateBasicProfile(
		context.Background(),
		goauth.NilSubjectID,
		goauth.BasicProfile{},
	)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = fixture.Runtime.UpdateBasicProfile(
		context.Background(),
		goauth.NewSubjectID(),
		goauth.BasicProfile{},
	)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)

	_, err = fixture.Runtime.ChangePassword(context.Background(), goauth.ChangePasswordRequest{})
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = fixture.Runtime.ChangePassword(context.Background(), goauth.ChangePasswordRequest{
		SubjectID:       registered.Account.Subject.ID,
		CurrentPassword: testPassword,
		NewPassword:     "short",
	})
	require.ErrorIs(t, err, goauth.ErrInvalidPassword)
	_, err = fixture.Runtime.ChangePassword(context.Background(), goauth.ChangePasswordRequest{
		SubjectID:       registered.Account.Subject.ID,
		CurrentPassword: wrongTestPassword,
		NewPassword:     "Lifecycle-Outcome-Replacement-1",
	})
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	_, err = fixture.Runtime.ChangePassword(context.Background(), goauth.ChangePasswordRequest{
		SubjectID:       registered.Account.Subject.ID,
		CurrentPassword: testPassword,
		NewPassword:     testPassword,
	})
	require.ErrorIs(t, err, goauth.ErrPasswordUnchanged)

	require.ErrorIs(
		t,
		fixture.Runtime.Logout(context.Background(), goauth.NilSubjectID, ""),
		goauth.ErrSessionRevoked,
	)
	require.NoError(t, fixture.Runtime.Logout(
		context.Background(),
		registered.Account.Subject.ID,
		registered.Tokens.Session.ID,
	))
	require.ErrorIs(
		t,
		fixture.Runtime.Logout(
			context.Background(),
			registered.Account.Subject.ID,
			registered.Tokens.Session.ID,
		),
		goauth.ErrSessionRevoked,
	)
	_, err = fixture.Runtime.LogoutAll(context.Background(), goauth.NilSubjectID)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
}

func TestEmailChangeTypedOutcomesAndLimits(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "email.change.outcomes@example.test")
	occupied := registerAccount(t, fixture, "email.change.occupied@example.test")

	require.ErrorIs(
		t,
		fixture.Runtime.RequestEmailChange(context.Background(), goauth.NilSubjectID, "new@example.test"),
		goauth.ErrAccountNotFound,
	)
	require.ErrorIs(
		t,
		fixture.Runtime.RequestEmailChange(
			context.Background(),
			goauth.NewSubjectID(),
			"new@example.test",
		),
		goauth.ErrAccountNotFound,
	)
	require.ErrorIs(
		t,
		fixture.Runtime.RequestEmailChange(
			context.Background(),
			registered.Account.Subject.ID,
			invalidTestEmail,
		),
		goauth.ErrInvalidIdentifier,
	)
	require.ErrorIs(
		t,
		fixture.Runtime.RequestEmailChange(
			context.Background(),
			registered.Account.Subject.ID,
			"EMAIL.CHANGE.OUTCOMES@EXAMPLE.TEST",
		),
		goauth.ErrEmailChangeSameValue,
	)
	require.ErrorIs(
		t,
		fixture.Runtime.RequestEmailChange(
			context.Background(),
			registered.Account.Subject.ID,
			occupied.Account.PrimaryEmail.DisplayValue,
		),
		goauth.ErrIdentifierAlreadyExists,
	)

	send := func(index int) error {
		return fixture.Runtime.RequestEmailChange(
			context.Background(),
			registered.Account.Subject.ID,
			"new."+string(rune('a'+index))+"@example.test",
		)
	}
	require.NoError(t, send(0))
	code := latestEmailChangeCode(t, fixture)
	require.ErrorIs(t, send(1), goauth.ErrConfirmationResendDelay)
	for index := 1; index < 5; index++ {
		now = now.Add(time.Minute + time.Second)
		require.NoError(t, send(index))
	}
	now = now.Add(time.Minute + time.Second)
	require.ErrorIs(t, send(5), goauth.ErrConfirmationRateLimited)

	for _, malformed := range []string{"", "12345", "abcdef"} {
		_, err = fixture.Runtime.ConfirmEmailChange(
			context.Background(),
			registered.Account.Subject.ID,
			malformed,
		)
		require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	}
	_, err = fixture.Runtime.ConfirmEmailChange(context.Background(), goauth.NewSubjectID(), "123456")
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	_, err = fixture.Runtime.ConfirmEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		code,
	)
	require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode, "a newer issuance invalidates an older code")
}

func TestEmailChangeExpiryAndAttemptExhaustion(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "email.change.expiry@example.test")
	require.NoError(t, fixture.Runtime.RequestEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		"email.change.expired@example.test",
	))
	code := latestEmailChangeCode(t, fixture)
	wrong := differentCode(code)
	for range 5 {
		_, err = fixture.Runtime.ConfirmEmailChange(
			context.Background(),
			registered.Account.Subject.ID,
			wrong,
		)
		require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	}
	_, err = fixture.Runtime.ConfirmEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		code,
	)
	require.ErrorIs(t, err, goauth.ErrConfirmationAttempts)

	expiring := registerAccount(t, fixture, "email.change.expiring@example.test")
	require.NoError(t, fixture.Runtime.RequestEmailChange(
		context.Background(),
		expiring.Account.Subject.ID,
		"email.change.expired.second@example.test",
	))
	expiredCode := latestEmailChangeCode(t, fixture)
	now = now.Add(11 * time.Minute)
	_, err = fixture.Runtime.ConfirmEmailChange(
		context.Background(),
		expiring.Account.Subject.ID,
		expiredCode,
	)
	require.ErrorIs(t, err, goauth.ErrConfirmationExpired)
}
