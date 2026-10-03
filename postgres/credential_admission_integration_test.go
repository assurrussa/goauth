//go:build integration

package postgres_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestPostgresCredentialProofUsesSeparateBoundedAdmission(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	config := runtimeConfig(t)
	config.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Hour, Limit: 2}
	config.CredentialVerificationRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 12}
	auth, err := postgres.NewRuntime(postgres.Config{
		DB: db, AutoMigrate: true, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auth.Close()) })
	const password = "Postgres-Credential-Admission-Passphrase-42"
	_, err = auth.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "credential-admission@example.test", Password: password,
	})
	require.NoError(t, err)
	credential := goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "credential-admission@example.test"},
		Password:   password,
	}
	for range 12 {
		proof, err := auth.PrepareCredential(t.Context(), credential)
		require.NoError(t, err)
		require.NotNil(t, proof)
	}
	_, err = auth.PrepareCredential(t.Context(), credential)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	for range 2 {
		_, err = auth.Login(t.Context(), goauth.LoginRequest{Credential: credential})
		require.NoError(t, err)
	}
	_, err = auth.Login(t.Context(), goauth.LoginRequest{Credential: credential})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}
