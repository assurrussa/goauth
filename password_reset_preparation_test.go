package goauth_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

type countedResetHasher struct {
	goauth.PasswordHasher
	calls int
	fail  error
	hook  func()
}

func (h *countedResetHasher) HashPassword(password string) (string, error) {
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
	resetLegacyFallback      = "legacy fallback"
	resetExpiryDuringHashing = "expiry while hashing"
	resetHashFailure         = "hash failure"
)

func TestDefaultResetAuthenticatesBeforeHashing(t *testing.T) {
	for _, scenario := range []string{
		"wrong digest",
		"missing record",
		"expired",
		"success and reuse",
		resetHashFailure,
		resetExpiryDuringHashing,
		resetLegacyFallback,
	} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
			hasher := &countedResetHasher{PasswordHasher: &legacyBcryptHasher{}}
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				c.PasswordHasher = hasher
				c.Now = func() time.Time { return now }
				if scenario == resetLegacyFallback {
					c.Store = noSubjectResetStore{RuntimeStore: c.Store}
				}
			})
			require.NoError(t, err)
			const email = "reset.preparation@example.test"
			registered := registerAccount(t, fixture, email)
			require.NoError(t, fixture.Runtime.RequestPasswordReset(t.Context(), email))
			token := recipientResetToken(t, fixture)
			before, err := fixture.Store.GetLocalAccount(t.Context(), registered.Account.Subject.ID)
			require.NoError(t, err)
			hasher.calls = 0
			var expected error
			switch scenario {
			case "wrong digest":
				parts := strings.Split(token, ".")
				require.Len(t, parts, 3)
				parts[2] = strings.Repeat("A", 43)
				token = strings.Join(parts, ".")
				expected = goauth.ErrInvalidToken
			case "missing record":
				parts := strings.Split(token, ".")
				require.Len(t, parts, 3)
				parts[1] = strings.Repeat("A", len(parts[1]))
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
			err = fixture.Runtime.ResetPassword(t.Context(), token, replacement)
			if expected != nil {
				require.ErrorIs(t, err, expected)
				after, lookupErr := fixture.Store.GetLocalAccount(t.Context(), registered.Account.Subject.ID)
				require.NoError(t, lookupErr)
				require.Equal(t, before, after)
				require.Len(t, fixture.Events.Events(), 1)
				if scenario != resetHashFailure && scenario != resetExpiryDuringHashing {
					require.Zero(t, hasher.calls)
					return
				}
				require.Equal(t, 1, hasher.calls)
				hasher.fail, hasher.hook = nil, nil
				if scenario == resetHashFailure {
					require.NoError(t, fixture.Runtime.ResetPassword(t.Context(), token, replacement))
					require.Equal(t, 2, hasher.calls)
					return
				}
				require.ErrorIs(t, fixture.Runtime.ResetPassword(t.Context(), token, replacement), goauth.ErrExpiredToken)
				require.Equal(t, 1, hasher.calls)
				return
			}
			require.NoError(t, err)
			require.Equal(t, 1, hasher.calls)
			require.ErrorIs(t, fixture.Runtime.ResetPassword(t.Context(), token, replacement), goauth.ErrResetAlreadyUsed)
			if scenario == resetLegacyFallback {
				require.Equal(t, 2, hasher.calls)
			} else {
				require.Equal(t, 1, hasher.calls)
			}
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
			require.ErrorIs(t, err, goauth.ErrSessionRevoked)
			require.Len(t, fixture.Events.Events(), 2)
		})
	}
}
