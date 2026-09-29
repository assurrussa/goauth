package goauth_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const reviewPassword = "Review-Unique-Passphrase-42"

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
	lockError error
}

func (s *reviewLockStore) LockAccount(ctx context.Context, id goauth.SubjectID) (goauth.Account, error) {
	if s.lockError != nil {
		return goauth.Account{}, s.lockError
	}
	account, err := s.RuntimeStore.LockAccount(ctx, id)
	if err == nil && s.afterLock != nil {
		s.afterLock()
	}
	return account, err
}

func TestReviewEmailChangePreservesLockFailure(t *testing.T) {
	var store *reviewLockStore
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		store = &reviewLockStore{RuntimeStore: config.Store}
		config.Store = store
	})
	require.NoError(t, err)
	account := reviewAccount(t, fixture)
	require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), account.Subject.ID, "replacement@example.test"))
	code := reviewCode(t, fixture)
	before := len(fixture.Events.Events())
	store.lockError = context.DeadlineExceeded
	confirmed, err := fixture.Runtime.ConfirmEmailChange(t.Context(), account.Subject.ID, code)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Zero(t, confirmed)
	require.Len(t, fixture.Events.Events(), before)
	store.lockError = nil
	_, err = fixture.Runtime.PendingEmailChange(t.Context(), account.Subject.ID)
	require.NoError(t, err)
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
				require.NoError(t, fixture.Runtime.SendEmailChallenge(
					t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification,
				))
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
		SubjectID: account.Subject.ID, CurrentPassword: "incorrect-review-password", NewPassword: "Different-Unique-Passphrase-42",
	}
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	var retry interface{ RetryAfter() time.Duration }
	require.ErrorAs(t, err, &retry)
	require.Equal(t, 17*time.Second, retry.RetryAfter())
	now = now.Add(18 * time.Second)
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
}

func TestReviewTestkitEmailInvalidationTiming(t *testing.T) {
	now := time.Now().UTC()
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
	})
	require.NoError(t, err)

	account := reviewAccount(t, fixture)
	id := account.Subject.ID

	_, err = fixture.Runtime.Login(t.Context(), goauth.LoginRequest{
		Realm: goauth.RealmUser,
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "review@example.test"},
			Password:   reviewPassword,
		},
	})
	require.NoError(t, err)

	// Sequence 1:
	// Prior to transaction: issue email change.
	require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), id, "new1@example.test"))
	oldCode := reviewCode(t, fixture)
	require.NotEmpty(t, oldCode)

	// Inside single transaction: RevokeSubjectSessions then try to verify old change.
	err = fixture.Store.InAuthTransaction(t.Context(), func(txCtx context.Context) error {
		count, err := fixture.Runtime.LogoutAll(txCtx, id)
		if err != nil {
			return err
		}
		require.EqualValues(t, 1, count)

		// Verification of old email change within the same transaction must fail immediately.
		_, err = fixture.Runtime.ConfirmEmailChange(txCtx, id, oldCode)
		require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
		return nil
	})
	require.NoError(t, err)

	// Sequence 2:
	// Advance clock past MinResendInterval (1 minute) to allow re-issuing:
	now = now.Add(2 * time.Minute)

	// Inside single transaction: RevokeSubjectSessions THEN issue new email change.
	err = fixture.Store.InAuthTransaction(t.Context(), func(txCtx context.Context) error {
		_, err := fixture.Runtime.LogoutAll(txCtx, id)
		if err != nil {
			return err
		}
		// Newly issued code after session revocation within same transaction must NOT be retroactively invalidated.
		return fixture.Runtime.RequestEmailChange(txCtx, id, "new2@example.test")
	})
	require.NoError(t, err)

	newCode := reviewCode(t, fixture)
	require.NotEmpty(t, newCode)
	verified, err := fixture.Runtime.ConfirmEmailChange(t.Context(), id, newCode)
	require.NoError(t, err)
	require.Equal(t, "new2@example.test", verified.PrimaryEmail.DisplayValue)

	// Direct store call:
	// Advance clock past MinResendInterval:
	now = now.Add(2 * time.Minute)

	// Issue pending email change, then call store.RevokeSubjectSessions directly without InAuthTransaction.
	require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), id, "new3@example.test"))
	directCode := reviewCode(t, fixture)
	require.NotEmpty(t, directCode)
	now = now.Add(time.Second)
	_, err = fixture.Store.RevokeSubjectSessions(t.Context(), id, now)
	require.NoError(t, err)
	_, err = fixture.Runtime.ConfirmEmailChange(t.Context(), id, directCode)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}

func TestReviewTestkitRateLimitReducedWindow(t *testing.T) {
	const testReducedLoginAction = "test_reduced_login"

	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)

	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	digest := goauth.SecretDigest{KeyID: "key-1", Digest: bytes.Repeat([]byte{7}, 32)}

	// Record 5 events: 12:00, 12:01, 12:02, 12:03, 12:04 with window = 1 hour.
	for i := 0; i < 5; i++ {
		eventTime := base.Add(time.Duration(i) * time.Minute)
		res, err := fixture.Store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
			Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 10, Now: eventTime,
		})
		require.NoError(t, err)
		require.True(t, res.Allowed)
	}

	// At 12:59, limit is reduced to 2.
	// Limiting event is 12:03 (index 2-1 = 1 from the newest [12:04, 12:03, 12:02, 12:01, 12:00]).
	// Expected deadline is 12:03 + 1h = 13:03.
	now := base.Add(59 * time.Minute)
	res, err := fixture.Store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: now,
	})
	require.NoError(t, err)
	require.False(t, res.Allowed)
	expectedRetry := base.Add(3 * time.Minute).Add(time.Hour)
	require.Equal(t, expectedRetry, res.RetryAt)

	// Check before deadline: 13:02:59 -> rejected
	resBefore, err := fixture.Store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: expectedRetry.Add(-time.Second),
	})
	require.NoError(t, err)
	require.False(t, resBefore.Allowed)

	// Check exact boundary: 13:03:00 -> rejected (cutoff is inclusive)
	resBoundary, err := fixture.Store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: expectedRetry,
	})
	require.NoError(t, err)
	require.False(t, resBoundary.Allowed)

	// Check after deadline: 13:03:01 -> allowed (12:03 has expired)
	resAfter, err := fixture.Store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: expectedRetry.Add(time.Second),
	})
	require.NoError(t, err)
	require.True(t, resAfter.Allowed)
}

func TestReviewTestkitNestedChangePasswordRollbackPreservesAttempt(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
	})
	require.NoError(t, err)

	account := reviewAccount(t, fixture)
	id := account.Subject.ID

	// Inside InAuthTransaction, call ChangePassword with wrong password.
	err = fixture.Store.InAuthTransaction(t.Context(), func(txCtx context.Context) error {
		if _, err := fixture.Store.LockAccount(txCtx, id); err != nil {
			return err
		}
		_, err := fixture.Runtime.ChangePassword(txCtx, goauth.ChangePasswordRequest{
			SubjectID:       id,
			CurrentPassword: "invalid-test-password",
			NewPassword:     "New-Unique-Passphrase-42",
		})
		return err
	})
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)

	// Attempt accounting must be preserved: next call must be rate-limited.
	_, err = fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID:       id,
		CurrentPassword: "invalid-test-password",
		NewPassword:     "New-Unique-Passphrase-42",
	})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}
