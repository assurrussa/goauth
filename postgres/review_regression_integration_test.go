//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/postgres"
)

func TestPostgresReviewOneTimeExpiryAfterLockWait(t *testing.T) {
	for _, kind := range []string{"reset", "verification", "email-change"} {
		t.Run(kind, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			db.SetMaxOpenConns(6)
			auth, err := postgres.NewRuntime(postgres.Config{
				DB: db, Runtime: runtimeConfig(t), NotificationSender: integrationNotificationSender(),
			})
			require.NoError(t, err)
			account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
				Email: "lock.review@example.test", Password: "Review-Lock-Unique-Passphrase-42",
			})
			require.NoError(t, err)
			store, err := postgres.NewStore(db)
			require.NoError(t, err)
			original, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			now := time.Now().UTC()
			expires := now.Add(time.Minute)
			digest := goauth.SecretDigest{KeyID: "review", Digest: bytes.Repeat([]byte{7}, 32)}
			id := uuid.NewString()
			var call func(context.Context) (string, error)
			var expected string
			switch kind {
			case "reset":
				require.NoError(t, store.CreatePasswordReset(t.Context(), goauth.PasswordResetRecord{
					SubjectID: account.Subject.ID, Selector: id, Digest: digest,
					ExpectedNormalizedEmail: account.PrimaryEmail.NormalizedValue,
					ExpectedSecurityVersion: account.Subject.SecurityVersion, CreatedAt: now, ExpiresAt: expires,
				}))
				expected = string(goauth.PasswordResetExpired)
				call = func(ctx context.Context) (string, error) {
					result, err := store.ConsumePasswordReset(ctx, goauth.PasswordResetConsumeRequest{
						Selector: id, Digest: digest, PasswordPHC: "must-not-be-persisted", Now: now,
					})
					return string(result.Status), err
				}
			case "verification":
				_, err := store.IssueEmailChallenge(t.Context(), goauth.EmailChallengeRecord{
					ID: id, SubjectID: account.Subject.ID, IdentifierID: account.PrimaryEmail.ID,
					ExpectedNormalizedEmail: account.PrimaryEmail.NormalizedValue,
					ExpectedSecurityVersion: account.Subject.SecurityVersion,
					Purpose:                 goauth.EmailChallengePurposeVerification, Digest: digest, RateDigest: digest,
					MaxAttempts: 5, CreatedAt: now, ExpiresAt: expires,
				}, goauth.EmailChallengeLimits{PerHour: 5, PerDay: 10})
				require.NoError(t, err)
				expected = string(goauth.EmailChallengeExpired)
				call = func(ctx context.Context) (string, error) {
					result, err := store.VerifyEmailChallenge(ctx, goauth.EmailChallengeVerifyRequest{
						SubjectID: account.Subject.ID, Purpose: goauth.EmailChallengePurposeVerification,
						Digests: []goauth.SecretDigest{digest}, Now: now,
					})
					return string(result.Status), err
				}
			default:
				_, err := store.IssueEmailChange(t.Context(), goauth.EmailChangeRecord{
					ID: id, SubjectID: account.Subject.ID,
					NewDisplayValue: "replacement@example.test", NewNormalizedValue: "replacement@example.test",
					Digest: digest, RateDigest: digest, MaxAttempts: 5, CreatedAt: now, ExpiresAt: expires,
				}, goauth.EmailChallengeLimits{PerHour: 5, PerDay: 10})
				require.NoError(t, err)
				expected = string(goauth.EmailChangeExpired)
				call = func(ctx context.Context) (string, error) {
					result, err := store.VerifyEmailChange(ctx, goauth.EmailChangeVerifyRequest{
						SubjectID: account.Subject.ID, Digests: []goauth.SecretDigest{digest}, Now: now,
					})
					return string(result.Status), err
				}
			}

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			var clock atomic.Int64
			clock.Store(now.UnixNano())
			ctx = authclock.With(ctx, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
			blocker, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = blocker.Rollback() }()
			var lockedID string
			require.NoError(t, blocker.QueryRowContext(ctx,
				`SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`, account.Subject.ID).Scan(&lockedID))
			var blockerPID int
			require.NoError(t, blocker.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID))
			type outcome struct {
				status string
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				status, err := call(ctx)
				done <- outcome{status: status, err: err}
			}()
			// Observe a real lock wait on an independent connection; no timing-only barrier.
			require.Eventually(t, func() bool {
				var waiting bool
				err := db.QueryRowContext(ctx, `SELECT EXISTS (
SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, blockerPID).Scan(&waiting)
				return err == nil && waiting
			}, 5*time.Second, 10*time.Millisecond)
			clock.Store(expires.Add(time.Second).UnixNano())
			require.NoError(t, blocker.Commit())
			select {
			case result := <-done:
				require.NoError(t, result.err)
				require.Equal(t, expected, result.status)
			case <-ctx.Done():
				t.Fatal("blocked verification did not finish")
			}
			unchanged, err := store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, original.PasswordPHC, unchanged.PasswordPHC)
			require.Equal(t, account.Subject.SecurityVersion, unchanged.Account.Subject.SecurityVersion)
			require.Equal(t, account.PrimaryEmail.NormalizedValue, unchanged.Account.PrimaryEmail.NormalizedValue)
		})
	}
}

func TestPostgresReviewLogoutAllCountsNewRevocationsAndInvalidatesEmail(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	auth, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: runtimeConfig(t), NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	registered, err := auth.Register(t.Context(), goauth.RegisterRequest{
		Email: "logout.review@example.test", Password: "Review-Logout-Unique-Passphrase-42",
	})
	require.NoError(t, err)
	id := registered.Account.Subject.ID
	require.NoError(t, auth.RequestEmailChange(t.Context(), id, "replacement@example.test"))
	count, err := auth.LogoutAll(t.Context(), id)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	_, err = auth.PendingEmailChange(t.Context(), id)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	count, err = auth.LogoutAll(t.Context(), id)
	require.NoError(t, err)
	require.Zero(t, count)
	_, err = auth.ConfirmEmailChange(t.Context(), goauth.NewSubjectID(), "123456")
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}

func TestPostgresReviewPasswordChangeMissingSubject(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	config := runtimeConfig(t)
	config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
	auth, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	request := goauth.ChangePasswordRequest{
		SubjectID: goauth.NewSubjectID(), CurrentPassword: "incorrect-review-password",
		NewPassword: "Different-Unique-Passphrase-42",
	}
	_, err = auth.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	var events int
	require.NoError(t, db.QueryRowContext(t.Context(),
		`SELECT count(*) FROM auth_rate_limit_events WHERE action = 'password_change'`).Scan(&events))
	require.Zero(t, events)

	// Existing credentials still consume the subject bucket before verification.
	account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "password.limit@example.test", Password: "Review-Unique-Passphrase-42",
	})
	require.NoError(t, err)
	request.SubjectID = account.Subject.ID
	_, err = auth.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	_, err = auth.ChangePassword(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}

func TestPostgresReviewNestedChangePasswordMultiAndSingleConn(t *testing.T) {
	for _, singleConn := range []bool{false, true} {
		name := "multi_conn"
		if singleConn {
			name = "single_conn"
		}
		t.Run(name, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			require.NoError(t, postgres.Migrate(t.Context(), db))
			if singleConn {
				db.SetMaxOpenConns(1)
				defer db.SetMaxOpenConns(0)
			}
			config := runtimeConfig(t)
			config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
			auth, err := postgres.NewRuntime(postgres.Config{
				DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
			})
			require.NoError(t, err)

			account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
				Email: name + "@example.test", Password: "Review-Unique-Passphrase-42",
			})
			require.NoError(t, err)
			subjectID := account.Subject.ID

			store, err := postgres.NewStore(db)
			require.NoError(t, err)

			// Outer InAuthTransaction holding lock on account, calling ChangePassword with wrong password.
			err = store.InAuthTransaction(t.Context(), func(txCtx context.Context) error {
				if _, err := store.LockAccount(txCtx, subjectID); err != nil {
					return err
				}
				_, err := auth.ChangePassword(txCtx, goauth.ChangePasswordRequest{
					SubjectID:       subjectID,
					CurrentPassword: "invalid-test-password",
					NewPassword:     "New-Unique-Passphrase-42",
				})
				return err
			})
			require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)

			// Verify attempt accounting was preserved across rollback:
			// next attempt must be rate-limited because Limit == 1.
			_, err = auth.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
				SubjectID:       subjectID,
				CurrentPassword: "invalid-test-password",
				NewPassword:     "New-Unique-Passphrase-42",
			})
			require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)

			// Now test successful password change inside InAuthTransaction
			account2, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
				Email: name + "2@example.test", Password: "Review-Unique-Passphrase-42",
			})
			require.NoError(t, err)
			subjectID2 := account2.Subject.ID

			err = store.InAuthTransaction(t.Context(), func(txCtx context.Context) error {
				if _, err := store.LockAccount(txCtx, subjectID2); err != nil {
					return err
				}
				_, err := auth.ChangePassword(txCtx, goauth.ChangePasswordRequest{
					SubjectID:       subjectID2,
					CurrentPassword: "Review-Unique-Passphrase-42",
					NewPassword:     "New-Unique-Passphrase-42",
				})
				return err
			})
			require.NoError(t, err)

			// Verify password was indeed changed.
			loginRes, err := auth.Login(t.Context(), goauth.LoginRequest{
				Realm: goauth.RealmUser,
				Credential: goauth.Credential{
					Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: name + "2@example.test"},
					Password:   "New-Unique-Passphrase-42",
				},
			})
			require.NoError(t, err)
			require.Equal(t, subjectID2, loginRes.Account.Subject.ID)
		})
	}
}

func TestPostgresReviewEmailInvalidationTiming(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	now := time.Now().UTC()
	config := runtimeConfig(t)
	config.Now = func() time.Time { return now }
	auth, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)

	account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "email.timing@example.test", Password: "Review-Unique-Passphrase-42",
	})
	require.NoError(t, err)
	id := account.Subject.ID

	_, err = auth.Login(t.Context(), goauth.LoginRequest{
		Realm: goauth.RealmUser,
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "email.timing@example.test"},
			Password:   "Review-Unique-Passphrase-42",
		},
	})
	require.NoError(t, err)

	// Sequence 1:
	// Prior to transaction: issue email change.
	require.NoError(t, auth.RequestEmailChange(t.Context(), id, "new1@example.test"))
	pending, err := auth.PendingEmailChange(t.Context(), id)
	require.NoError(t, err)
	require.NotEmpty(t, pending.ID)

	// Inside single transaction: RevokeSubjectSessions then try to verify old change.
	err = store.InAuthTransaction(t.Context(), func(txCtx context.Context) error {
		count, err := auth.LogoutAll(txCtx, id)
		if err != nil {
			return err
		}
		require.EqualValues(t, 1, count)

		// Verification of old email change within the same transaction must fail immediately.
		_, err = auth.ConfirmEmailChange(txCtx, id, "000000")
		require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
		return nil
	})
	require.NoError(t, err)

	// Sequence 2:
	// Advance clock past MinResendInterval (1 minute) to allow re-issuing:
	now = now.Add(2 * time.Minute)

	// Inside single transaction: RevokeSubjectSessions THEN issue new email change.
	err = store.InAuthTransaction(t.Context(), func(txCtx context.Context) error {
		_, err := auth.LogoutAll(txCtx, id)
		if err != nil {
			return err
		}
		// Newly issued code after session revocation within same transaction must NOT be retroactively invalidated.
		return auth.RequestEmailChange(txCtx, id, "new2@example.test")
	})
	require.NoError(t, err)

	pending2, err := auth.PendingEmailChange(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, "new2@example.test", pending2.NewDisplayValue)

	// Direct store call:
	// Advance clock past MinResendInterval:
	now = now.Add(2 * time.Minute)

	// Issue pending email change, then call store.RevokeSubjectSessions directly without InAuthTransaction.
	require.NoError(t, auth.RequestEmailChange(t.Context(), id, "new3@example.test"))
	now = now.Add(time.Second)
	_, err = store.RevokeSubjectSessions(t.Context(), id, now)
	require.NoError(t, err)
	_, err = auth.PendingEmailChange(t.Context(), id)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}

func TestPostgresReviewAuthenticationRateLimitReducedWindow(t *testing.T) {
	const testReducedLoginAction = "test_reduced_login"

	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	store, err := postgres.NewStore(db)
	require.NoError(t, err)

	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	digest := goauth.SecretDigest{KeyID: "key-1", Digest: bytes.Repeat([]byte{7}, 32)}

	// Record 5 events: 12:00, 12:01, 12:02, 12:03, 12:04 with window = 1 hour.
	for i := 0; i < 5; i++ {
		eventTime := base.Add(time.Duration(i) * time.Minute)
		res, err := store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
			Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 10, Now: eventTime,
		})
		require.NoError(t, err)
		require.True(t, res.Allowed)
	}

	// At 12:59, limit is reduced to 2.
	// Limiting event is 12:03 (index 2-1 = 1 from the newest [12:04, 12:03, 12:02, 12:01, 12:00]).
	// Expected deadline is 12:03 + 1h = 13:03.
	now := base.Add(59 * time.Minute)
	res, err := store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: now,
	})
	require.NoError(t, err)
	require.False(t, res.Allowed)
	expectedRetry := base.Add(3 * time.Minute).Add(time.Hour)
	require.Equal(t, expectedRetry, res.RetryAt)

	// Check before deadline: 13:02:59 -> rejected
	resBefore, err := store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: expectedRetry.Add(-time.Second),
	})
	require.NoError(t, err)
	require.False(t, resBefore.Allowed)

	// Check exact boundary: 13:03:00 -> rejected (occurred_at >= cutoff is inclusive, so 12:03 is included)
	resBoundary, err := store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: expectedRetry,
	})
	require.NoError(t, err)
	require.False(t, resBoundary.Allowed)

	// Check after deadline: 13:03:01 -> allowed (12:03 is now strictly older than 1 hour, so only 12:04 remains in window)
	resAfter, err := store.TakeRateLimit(t.Context(), goauth.RateLimitRequest{
		Action: testReducedLoginAction, Bucket: digest, Window: time.Hour, Limit: 2, Now: expectedRetry.Add(time.Second),
	})
	require.NoError(t, err)
	require.True(t, resAfter.Allowed)
}
