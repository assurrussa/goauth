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
