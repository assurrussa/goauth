//go:build integration

package postgres_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

type postgresResetHasher struct {
	goauth.PasswordHasher
	calls int
	fail  error
	hook  func()
}

func (h *postgresResetHasher) HashPassword(password string) (string, error) {
	h.calls++
	if h.hook != nil {
		h.hook()
	}
	if h.fail != nil {
		return "", h.fail
	}
	return h.PasswordHasher.HashPassword(password)
}

const (
	resetExpiryDuringHashing = "expiry while hashing"
	resetHashFailure         = "hash failure"
)

func TestPostgresDefaultResetAuthenticatesBeforeHashing(t *testing.T) {
	for _, scenario := range []string{
		"wrong digest",
		"missing record",
		"expired",
		"success and reuse",
		resetHashFailure,
		resetExpiryDuringHashing,
	} {
		t.Run(scenario, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
			require.NoError(t, err)
			hasher := &postgresResetHasher{PasswordHasher: base}
			now := time.Now().UTC()
			config := runtimeConfig(t)
			config.PasswordHasher = hasher
			config.Now = func() time.Time { return now }
			runtime, err := postgres.NewRuntime(postgres.Config{
				DB: db, AutoMigrate: true, Runtime: config, NotificationSender: integrationNotificationSender(),
			})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, runtime.Close()) })
			const email = "reset.preparation@example.test"
			registered := register(t, runtime, email)
			require.NoError(t, runtime.RequestPasswordReset(t.Context(), email))
			_, notification := queuedNotification(t, db, registered.Account.Subject.ID, "password_reset")
			resetURL, err := url.Parse(notification.Data["reset_url"])
			require.NoError(t, err)
			token := resetURL.Query().Get("token")
			require.NotEmpty(t, token)
			store, err := postgres.NewStore(db)
			require.NoError(t, err)
			before, err := store.GetLocalAccount(t.Context(), registered.Account.Subject.ID)
			require.NoError(t, err)
			hasher.calls = 0
			var expected error
			switch scenario {
			case "wrong digest", "missing record":
				parts := strings.Split(token, ".")
				require.Len(t, parts, 3)
				if scenario == "wrong digest" {
					parts[2] = strings.Repeat("A", 43)
				} else {
					parts[1] = strings.Repeat("A", len(parts[1]))
				}
				token = strings.Join(parts, ".")
				expected = goauth.ErrInvalidToken
			case "expired":
				now = now.Add(16 * time.Minute)
				expected = goauth.ErrExpiredToken
			case resetHashFailure:
				expected = errors.New("synthetic hash failure")
				hasher.fail = expected
			case resetExpiryDuringHashing:
				hasher.hook = func() { now = now.Add(16 * time.Minute) }
				expected = goauth.ErrExpiredToken
			}
			const replacement = "Replacement-Preparation-Passphrase-42"
			err = runtime.ResetPassword(t.Context(), token, replacement)
			if expected != nil {
				require.ErrorIs(t, err, expected)
				after, lookupErr := store.GetLocalAccount(t.Context(), registered.Account.Subject.ID)
				require.NoError(t, lookupErr)
				require.Equal(t, before, after)
				var consumed, success int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_password_reset_records WHERE subject_id=$1 AND consumed_at IS NOT NULL`, registered.Account.Subject.ID).Scan(&consumed))
				require.Zero(t, consumed)
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_notification_deliveries WHERE subject_id=$1 AND event_type='password_reset_success'`, registered.Account.Subject.ID).Scan(&success))
				require.Zero(t, success)
				if scenario != resetHashFailure && scenario != resetExpiryDuringHashing {
					require.Zero(t, hasher.calls)
					return
				}
				require.Equal(t, 1, hasher.calls)
				hasher.fail, hasher.hook = nil, nil
				if scenario == resetHashFailure {
					require.NoError(t, runtime.ResetPassword(t.Context(), token, replacement))
					require.Equal(t, 2, hasher.calls)
					return
				}
				require.ErrorIs(t, runtime.ResetPassword(t.Context(), token, replacement), goauth.ErrExpiredToken)
				require.Equal(t, 1, hasher.calls)
				return
			}
			require.NoError(t, err)
			require.Equal(t, 1, hasher.calls)
			require.ErrorIs(t, runtime.ResetPassword(t.Context(), token, replacement), goauth.ErrResetAlreadyUsed)
			require.Equal(t, 1, hasher.calls)
			_, err = runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
			require.ErrorIs(t, err, goauth.ErrSessionRevoked)
		})
	}
}
