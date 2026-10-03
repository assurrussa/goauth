package goauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

//nolint:gosec // Isolated test fixture, never a real credential.
const admissionPassword = "Isolated-Credential-Admission-Passphrase-42"

func TestCredentialAdmissionSeparatesRepeatedSuccessFromLoginAndPasswordChange(t *testing.T) {
	f, err := testkit.NewRuntime(func(config *goauth.Config) {
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

	credential.Password = "wrong-synthetic-passphrase"
	for range 2 {
		_, err = f.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: credential})
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials, "credential admission must not consume the login bucket")
	}
	credential.Password = admissionPassword
	_, err = f.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: credential})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited, "login must retain its smaller configured limit")

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
}

func TestCredentialAdmissionDefaultsToExistingLoginPolicy(t *testing.T) {
	f, err := testkit.NewRuntime(func(config *goauth.Config) {
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

func TestCredentialAdmissionBoundsRepeatedLegacyIdentityChecks(t *testing.T) {
	f := localIdentityFixture(t, func(config *goauth.Config) {
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
