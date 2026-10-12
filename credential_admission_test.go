package goauth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

//nolint:gosec // Isolated test fixture, never a real credential.
const admissionPassword = "Isolated-Credential-Admission-Passphrase-42"

func TestCredentialAdmissionSeparatesRepeatedSuccessFromLoginAndPasswordChange(t *testing.T) {
	hasher := &admissionTestHasher{}
	f, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.PasswordHasher = hasher
		// Keep admission attempts in one window regardless of real hashing duration.
		config.Now = func() time.Time { return time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC) }
		config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Hour, Limit: 2}
		config.CredentialVerificationRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 12}
	})
	require.NoError(t, err)
	account, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "admission@example.test", Password: admissionPassword,
	})
	require.NoError(t, err)
	credential := goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: " ADMISSION@example.test "},
		Password:   admissionPassword,
	}
	for range 12 {
		verified, err := f.Runtime.VerifyCredential(t.Context(), credential)
		require.NoError(t, err, "successful per-request checks must use the explicit credential policy")
		require.Equal(t, account.Subject.ID, verified.Subject.ID)
	}
	credential.Identifier.Value = "admission@example.test"
	_, err = f.Runtime.VerifyCredential(t.Context(), credential)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	require.Equal(t, 12, hasher.verifications, "rate-limited credential checks must not reach the hasher")

	credential.Password = "wrong-synthetic-passphrase"
	for range 2 {
		_, err = f.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: credential})
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials, "credential admission must not consume the login bucket")
	}
	credential.Password = admissionPassword
	_, err = f.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: credential})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited, "login must retain its smaller configured limit")
	require.Equal(t, 14, hasher.verifications, "rate-limited login must not reach the hasher")

	for range 2 {
		_, err = f.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
			SubjectID: account.Subject.ID, CurrentPassword: "wrong-synthetic-passphrase", NewPassword: "New-Admission-Passphrase-42",
		})
		require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	}
	_, err = f.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: admissionPassword, NewPassword: "New-Admission-Passphrase-42",
	})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited,
		"password changes must retain their smaller configured limit")
	require.Equal(t, 16, hasher.verifications, "rate-limited password changes must not reach the hasher")
}

func TestCredentialAdmissionDefaultsToExistingLoginPolicy(t *testing.T) {
	hasher := &admissionTestHasher{}
	f, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.PasswordHasher = hasher
		// Keep admission attempts in one window regardless of real hashing duration.
		config.Now = func() time.Time { return time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC) }
		config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 3}
	})
	require.NoError(t, err)
	_, err = f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "inherited@example.test", Password: admissionPassword,
	})
	require.NoError(t, err)
	credential := goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "inherited@example.test"},
		Password:   admissionPassword,
	}
	for range 3 {
		_, err = f.Runtime.VerifyCredential(t.Context(), credential)
		require.NoError(t, err)
	}
	_, err = f.Runtime.VerifyCredential(t.Context(), credential)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	require.Equal(t, 3, hasher.verifications, "inherited admission must reject before the hasher")
}

func TestCredentialAdmissionRejectsUnboundedOrPartialPolicy(t *testing.T) {
	for _, policy := range []goauth.RateLimitPolicy{
		{Limit: 1},
		{Window: time.Minute},
		{Window: time.Minute, Limit: -1},
		{Window: time.Minute, Limit: 10001},
		{Window: 25 * time.Hour, Limit: 1},
	} {
		_, err := testkit.NewRuntime(func(config *goauth.Config) {
			config.CredentialVerificationRateLimit = policy
		})
		require.Error(t, err)
	}
}

// admissionTestHasher uses a deliberately cheap digest for synthetic test credentials only.
// Its counter is used only by the sequential admission tests above.
type admissionTestHasher struct{ verifications int }

func (*admissionTestHasher) HashPassword(password string) (string, error) {
	digest := sha256.Sum256([]byte(password))
	return hex.EncodeToString(digest[:]), nil
}

func (h *admissionTestHasher) VerifyPassword(phc, password string) error {
	h.verifications++
	digest := sha256.Sum256([]byte(password))
	if phc != hex.EncodeToString(digest[:]) {
		return goauth.ErrInvalidCredentials
	}
	return nil
}
