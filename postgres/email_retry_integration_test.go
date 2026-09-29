//go:build integration

package postgres_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestPostgresReviewEmailQuotaRetryDeadline(t *testing.T) {
	for _, change := range []bool{false, true} {
		for _, window := range []time.Duration{time.Hour, 24 * time.Hour} {
			name := map[bool]string{false: "verification", true: "email-change"}[change] + "/" + window.String()
			t.Run(name, func(t *testing.T) {
				db := integrationDB(t)
				resetSchema(t, db)
				require.NoError(t, postgres.Migrate(t.Context(), db))
				base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
				now := base
				config := runtimeConfig(t)
				config.Now = func() time.Time { return now }
				auth, err := postgres.NewRuntime(postgres.Config{
					DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
				})
				require.NoError(t, err)
				account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
					Email: "email.retry@example.test", Password: "Review-Retry-Unique-Passphrase-42",
				})
				require.NoError(t, err)
				issue := func() error {
					if change {
						return auth.RequestEmailChange(t.Context(), account.Subject.ID, "replacement@example.test")
					}
					return auth.SendEmailChallenge(t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification)
				}
				count, spacing := 5, time.Minute
				if window == 24*time.Hour {
					count, spacing = 10, 2*time.Hour
				}
				for index := range count {
					now = base.Add(time.Duration(index) * spacing)
					require.NoError(t, issue())
				}
				now = base.Add(time.Duration(count-1)*spacing + 30*time.Second)
				err = issue()
				require.ErrorIs(t, err, goauth.ErrConfirmationResendDelay)
				var retry interface{ RetryAfter() time.Duration }
				require.ErrorAs(t, err, &retry)
				require.Equal(t, base.Add(window).Sub(now), retry.RetryAfter(), "the longer quota must determine the deadline")

				now = base.Add(window - time.Minute)
				err = issue()
				require.ErrorIs(t, err, goauth.ErrConfirmationRateLimited)
				require.ErrorAs(t, err, &retry)
				require.Equal(t, time.Minute, retry.RetryAfter())

				now = base.Add(window)
				require.ErrorIs(t, issue(), goauth.ErrConfirmationRateLimited, "the exact cutoff stays included")
				var deliveries int
				require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM auth_notification_deliveries
WHERE subject_id = $1 AND event_type IN ('email_change', 'email_challenge')`, account.Subject.ID).Scan(&deliveries))
				require.Equal(t, count, deliveries, "denials must not enqueue a notification")
				now = now.Add(time.Microsecond)
				require.NoError(t, issue())
			})
		}
	}
}

func TestPostgresReviewEmailQuotaAfterReducedLimit(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	auth, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: runtimeConfig(t), NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	account, err := auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "quota.reduced@example.test", Password: "Review-Retry-Unique-Passphrase-42",
	})
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	limits := goauth.EmailChallengeLimits{MinResendInterval: time.Minute, PerHour: 5, PerDay: 10}
	issue := func(index int, at time.Time) goauth.EmailChangeIssueResult {
		t.Helper()
		email := fmt.Sprintf("new.%d@example.test", index)
		result, issueErr := store.IssueEmailChange(t.Context(), goauth.EmailChangeRecord{
			ID: goauth.NewSubjectID().String(), SubjectID: account.Subject.ID,
			NewDisplayValue: email, NewNormalizedValue: email,
			Digest:      goauth.SecretDigest{KeyID: "code", Digest: bytes.Repeat([]byte{1}, 32)},
			RateDigest:  goauth.SecretDigest{KeyID: "rate", Digest: bytes.Repeat([]byte{2}, 32)},
			MaxAttempts: 5, CreatedAt: at, ExpiresAt: at.Add(time.Hour),
		}, limits)
		require.NoError(t, issueErr)
		return result
	}
	for index := range 5 {
		require.Equal(t, goauth.EmailChangeIssued, issue(index, base.Add(time.Duration(index)*time.Minute)).Status)
	}
	limits.PerHour = 2
	denied := issue(5, base.Add(5*time.Minute))
	require.Equal(t, goauth.EmailChangeHourlyLimit, denied.Status)
	require.Equal(t, base.Add(time.Hour+3*time.Minute), denied.RetryAt.UTC())
}
