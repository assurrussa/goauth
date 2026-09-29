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

// Moved from review_regression_test.go without weakening the email-state checks.
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
	require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), id, "new1@example.test"))
	oldCode := reviewCode(t, fixture)
	err = fixture.Store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		count, err := fixture.Runtime.LogoutAll(ctx, id)
		if err != nil {
			return err
		}
		require.EqualValues(t, 1, count)
		_, err = fixture.Runtime.ConfirmEmailChange(ctx, id, oldCode)
		require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
		return nil
	})
	require.NoError(t, err)
	now = now.Add(2 * time.Minute)
	err = fixture.Store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		if _, err := fixture.Runtime.LogoutAll(ctx, id); err != nil {
			return err
		}
		return fixture.Runtime.RequestEmailChange(ctx, id, "new2@example.test")
	})
	require.NoError(t, err)
	verified, err := fixture.Runtime.ConfirmEmailChange(t.Context(), id, reviewCode(t, fixture))
	require.NoError(t, err)
	require.Equal(t, "new2@example.test", verified.PrimaryEmail.DisplayValue)
	now = now.Add(2 * time.Minute)
	require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), id, "new3@example.test"))
	directCode := reviewCode(t, fixture)
	now = now.Add(time.Second)
	_, err = fixture.Store.RevokeSubjectSessions(t.Context(), id, now)
	require.NoError(t, err)
	_, err = fixture.Runtime.ConfirmEmailChange(t.Context(), id, directCode)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}

func TestReviewTestkitRateLimitReducedWindow(t *testing.T) {
	store := testkit.NewStore()
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	request := goauth.RateLimitRequest{
		Action: "test_reduced_login", Bucket: goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{7}, 32)},
		Window: time.Hour, Limit: 10,
	}
	for i := range 5 {
		request.Now = base.Add(time.Duration(i) * time.Minute)
		result, err := store.TakeRateLimit(t.Context(), request)
		require.NoError(t, err)
		require.True(t, result.Allowed)
	}
	request.Limit = 2
	deadline := base.Add(63 * time.Minute)
	for _, at := range []time.Time{base.Add(59 * time.Minute), deadline.Add(-time.Second), deadline} {
		request.Now = at
		result, err := store.TakeRateLimit(t.Context(), request)
		require.NoError(t, err)
		require.False(t, result.Allowed)
		require.True(t, deadline.Equal(result.RetryAt))
	}
	request.Now = deadline.Add(time.Second)
	result, err := store.TakeRateLimit(t.Context(), request)
	require.NoError(t, err)
	require.True(t, result.Allowed)
}

func TestReviewTestkitNestedChangePasswordRejected(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Hour, Limit: 1}
	})
	require.NoError(t, err)
	account := reviewAccount(t, fixture)
	before, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	events := len(fixture.Events.Events())
	request := goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: reviewPassword, NewPassword: "New-Unique-Passphrase-42",
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- fixture.Store.InAuthTransaction(ctx, func(txCtx context.Context) error {
			if _, err := fixture.Store.LockAccount(txCtx, account.Subject.ID); err != nil {
				return err
			}
			_, err := fixture.Runtime.ChangePassword(txCtx, request)
			return err
		})
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, goauth.ErrRateLimitTransactionUnsupported)
	case <-ctx.Done():
		t.Fatal("nested ChangePassword waited for the outer lock")
	}
	after, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Len(t, fixture.Events.Events(), events)
	// Rejection precedes authentication and consumes no attempt. A standalone
	// wrong password is counted independently and the following call is limited.
	request.CurrentPassword = "incorrect-review-password"
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	_, err = fixture.Runtime.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}
