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

const reviewPassword = "Review-Unique-Passphrase-42" //nolint:gosec // Isolated test credential.

func reviewAccount(t *testing.T, fixture *testkit.Fixture) goauth.Account {
	t.Helper()
	account, err := fixture.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "review@example.test", Password: reviewPassword,
	})
	require.NoError(t, err)
	return account
}

func reviewCode(t *testing.T, fixture *testkit.Fixture) string {
	t.Helper()
	events := fixture.Events.Events()
	require.NotEmpty(t, events)
	notification, err := testkit.DecryptNotification(fixture.EnvelopeKeys, events[len(events)-1].Envelope)
	require.NoError(t, err)
	require.Len(t, notification.Data["code"], 6)
	return notification.Data["code"]
}

func TestReviewInactiveAccountCannotConfirmEmail(t *testing.T) {
	for _, status := range []goauth.SubjectStatus{"suspended", "disabled"} {
		t.Run(string(status), func(t *testing.T) {
			fixture, err := testkit.NewRuntime()
			require.NoError(t, err)
			account := reviewAccount(t, fixture)
			require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), account.Subject.ID, "replacement@example.test"))
			code := reviewCode(t, fixture)
			_, err = fixture.Runtime.SetSubjectStatus(t.Context(), account.Subject.ID, status)
			require.NoError(t, err)
			before := len(fixture.Events.Events())
			_, err = fixture.Runtime.ConfirmEmailChange(t.Context(), account.Subject.ID, code)
			require.ErrorIs(t, err, goauth.ErrAccountUnavailable)
			_, err = fixture.Runtime.VerifyEmailChallenge(t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification, code)
			require.ErrorIs(t, err, goauth.ErrAccountUnavailable)
			unchanged, err := fixture.Runtime.GetAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, account.PrimaryEmail.NormalizedValue, unchanged.PrimaryEmail.NormalizedValue)
			require.Len(t, fixture.Events.Events(), before)
		})
	}
}

func TestReviewLogoutAllInvalidatesPendingEmailChange(t *testing.T) {
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)
	account := reviewAccount(t, fixture)
	require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), account.Subject.ID, "replacement@example.test"))
	code := reviewCode(t, fixture)
	_, err = fixture.Runtime.LogoutAll(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	_, err = fixture.Runtime.ConfirmEmailChange(t.Context(), account.Subject.ID, code)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}

type reviewLockStore struct {
	goauth.RuntimeStore
	afterLock func()
}

func (s *reviewLockStore) LockAccount(ctx context.Context, id goauth.SubjectID) (goauth.Account, error) {
	account, err := s.RuntimeStore.LockAccount(ctx, id)
	if err == nil && s.afterLock != nil {
		s.afterLock()
	}
	return account, err
}

func TestReviewEmailExpiryIsCheckedAfterSubjectLock(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(map[bool]string{false: "verification", true: "email change"}[change], func(t *testing.T) {
			now := time.Now().UTC()
			var store *reviewLockStore
			fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
				config.Now = func() time.Time { return now }
				config.ChallengeTTL = time.Minute
				config.EmailChangeTTL = time.Minute
				store = &reviewLockStore{RuntimeStore: config.Store}
				config.Store = store
			})
			require.NoError(t, err)
			account := reviewAccount(t, fixture)
			if change {
				require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), account.Subject.ID, "replacement@example.test"))
			} else {
				require.NoError(t, fixture.Runtime.SendEmailChallenge(t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification))
			}
			code := reviewCode(t, fixture)
			store.afterLock = func() { now = now.Add(2 * time.Minute) }
			before := len(fixture.Events.Events())
			if change {
				_, err = fixture.Runtime.ConfirmEmailChange(t.Context(), account.Subject.ID, code)
			} else {
				_, err = fixture.Runtime.VerifyEmailChallenge(t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification, code)
			}
			require.ErrorIs(t, err, goauth.ErrConfirmationExpired)
			require.Len(t, fixture.Events.Events(), before)
		})
	}
}

func TestReviewPasswordChangeRateLimitRetainsDeadline(t *testing.T) {
	now := time.Now().UTC()
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
		config.LoginRateLimit = goauth.RateLimitPolicy{Window: 17 * time.Second, Limit: 1}
	})
	require.NoError(t, err)
	account := reviewAccount(t, fixture)
	request := goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: "wrong-password", NewPassword: "Different-Unique-Passphrase-42",
	}
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	var retry interface{ RetryAfter() time.Duration }
	require.True(t, errors.As(err, &retry))
	require.Equal(t, 17*time.Second, retry.RetryAfter())
	now = now.Add(18 * time.Second)
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
}
