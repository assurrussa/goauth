package goauth_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func TestPasswordResetAndConfirmationExpiryOutcomes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "expiry@example.test")

	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), "expiry@example.test"))
	resetEvent := fixture.Events.Events()[0]
	resetNotification, err := fixture.Runtime.DecryptNotificationEvent(resetEvent)
	require.NoError(t, err)
	resetURL, err := url.Parse(resetNotification.Data["reset_url"])
	require.NoError(t, err)
	now = now.Add(16 * time.Minute)
	require.ErrorIs(
		t,
		fixture.Runtime.ResetPassword(context.Background(), resetURL.Query().Get("token"), "Replacement-Expiry-1"),
		goauth.ErrExpiredToken,
	)

	now = now.Add(time.Minute)
	require.NoError(t, fixture.Runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	code := latestChallengeCode(t, fixture)
	now = now.Add(11 * time.Minute)
	_, err = fixture.Runtime.VerifyEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		code,
	)
	require.ErrorIs(t, err, goauth.ErrConfirmationExpired)
}

func TestConfirmationResendAndHourlyRateOutcomes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "rate.outcomes@example.test")
	send := func() error {
		return fixture.Runtime.SendEmailChallenge(
			context.Background(),
			registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification,
		)
	}
	require.NoError(t, send())
	require.ErrorIs(t, send(), goauth.ErrConfirmationResendDelay)
	for range 4 {
		now = now.Add(time.Minute + time.Second)
		require.NoError(t, send())
	}
	now = now.Add(time.Minute + time.Second)
	require.ErrorIs(t, send(), goauth.ErrConfirmationRateLimited)
}

func TestAlreadyVerifiedStatusAndRealmDenials(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "outcomes@example.test")

	_, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("outcomes@example.test", testPassword, goauth.RealmAdmin),
	)
	require.ErrorIs(t, err, goauth.ErrEmailVerificationRequired)
	verifyEmail(t, fixture, registered.Account.Subject.ID)
	account, err := fixture.Runtime.VerifyEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		latestChallengeCode(t, fixture),
	)
	require.NoError(t, err)
	require.True(t, account.EmailVerified())

	unchanged, err := fixture.Runtime.SetSubjectStatus(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.SubjectStatusActive,
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), unchanged.SecurityVersion)
	_, err = fixture.Runtime.SetSubjectStatus(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.SubjectStatus("unknown"),
	)
	require.ErrorIs(t, err, goauth.ErrInvalidSubjectStatus)
}

func TestRuntimeEventCleanupAndFunctionHooks(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
	})
	require.NoError(t, err)
	registerAccount(t, fixture, "cleanup@example.test")
	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), "cleanup@example.test"))
	now = now.Add(25 * time.Hour)
	deleted, err := fixture.Runtime.CleanupExpiredEncryptedEvents(context.Background())
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)

	resolver := goauth.IdentifierResolverFunc(func(_ context.Context, input goauth.IdentifierInput) (goauth.IdentifierInput, error) {
		input.Value = "normalized"
		return input, nil
	})
	resolved, err := resolver.NormalizeIdentifier(
		context.Background(),
		goauth.IdentifierInput{Scheme: employeeIdentifierScheme, Value: "raw"},
	)
	require.NoError(t, err)
	require.Equal(t, "normalized", resolved.Value)
	renderer := goauth.NotificationRendererFunc(func(_ context.Context, notification goauth.Notification) ([]byte, error) {
		return []byte(notification.Template), nil
	})
	payload, err := renderer.RenderNotification(
		context.Background(),
		goauth.Notification{Template: testNotificationTemplate},
	)
	require.NoError(t, err)
	require.Equal(t, []byte(testNotificationTemplate), payload)
}

func TestRuntimeRejectsInvalidRecoveryAndRealmInputs(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "invalid.outcomes@example.test")

	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), "missing@example.test"))
	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), invalidTestEmail))
	require.ErrorIs(
		t,
		fixture.Runtime.ResetPassword(context.Background(), "bad-token", "Replacement-Password-1"),
		goauth.ErrInvalidToken,
	)
	require.ErrorIs(
		t,
		fixture.Runtime.ResetPassword(context.Background(), "bad-token", "password123"),
		goauth.ErrCommonPassword,
	)
	require.ErrorIs(
		t,
		fixture.Runtime.SendEmailChallenge(context.Background(), goauth.NilSubjectID, goauth.EmailChallengePurposeVerification),
		goauth.ErrAccountNotFound,
	)
	require.Error(t, fixture.Runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurpose("phone"),
	))
	for _, code := range []string{"", "12345", "abcdef"} {
		_, err := fixture.Runtime.VerifyEmailChallenge(
			context.Background(),
			registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification,
			code,
		)
		require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	}
	_, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("invalid.outcomes@example.test", testPassword, "unregistered"),
	)
	require.ErrorIs(t, err, goauth.ErrRealmNotRegistered)

	_, err = fixture.Runtime.SetSubjectStatus(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.SubjectStatusDisabled,
	)
	require.NoError(t, err)
	require.ErrorIs(
		t,
		fixture.Runtime.SendEmailChallenge(
			context.Background(),
			registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification,
		),
		goauth.ErrAccountUnavailable,
	)
}

func TestRuntimeFailsClosedOnMembershipAndHookErrors(t *testing.T) {
	t.Parallel()
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.MembershipGate = goauth.MembershipGateFunc(func(context.Context, goauth.Realm, goauth.Account) error {
			return context.Canceled
		})
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "membership.denied@example.test")
	verifyEmail(t, fixture, registered.Account.Subject.ID)
	_, err = fixture.Runtime.Login(
		context.Background(),
		loginRequest("membership.denied@example.test", testPassword, goauth.RealmAdmin),
	)
	require.ErrorIs(t, err, goauth.ErrMembershipDenied)

	brokenResolverFixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			employeeIdentifierScheme: goauth.IdentifierResolverFunc(func(
				context.Context,
				goauth.IdentifierInput,
			) (goauth.IdentifierInput, error) {
				return goauth.IdentifierInput{Scheme: "other", Value: "value"}, nil
			}),
		}
	})
	require.NoError(t, err)
	_, err = brokenResolverFixture.Runtime.Login(context.Background(), goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: employeeIdentifierScheme, Value: "E-1"},
			Password:   testPassword,
		},
	})
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
}
