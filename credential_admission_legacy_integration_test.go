//go:build integration

package goauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestCredentialAdmissionBoundsRepeatedLegacyIdentityChecks(t *testing.T) {
	f := localIdentityFixture(t, func(config *goauth.Config) {
		// Keep admission attempts in one window regardless of real hashing duration.
		config.Now = func() time.Time { return time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC) }
		config.CredentialVerificationRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 12}
	})
	password := strings.Repeat("x", 129)
	request := localIdentityImport(password)
	account, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
	require.NoError(t, err)
	credential := goauth.Credential{Identifier: request.Identifier, Password: password}
	for range 12 {
		verified, err := f.Runtime.VerifyCredential(t.Context(), credential)
		require.NoError(t, err)
		require.Equal(t, account.Subject.ID, verified.Subject.ID)
		require.Zero(t, verified.PrimaryEmail)
	}
	_, err = f.Runtime.VerifyCredential(t.Context(), credential)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}
