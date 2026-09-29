//go:build integration

package redis_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
	goauthredis "github.com/assurrussa/goauth/redis"
)

func TestRedisAuthorizationCodePreservesSecurityVersion(t *testing.T) {
	client := integrationRedis(t)
	state, err := goauthredis.NewOIDCState(goauthredis.OIDCConfig{Client: client, Prefix: "review-version:"})
	require.NoError(t, err)
	now := time.Now().UTC()
	record := oidc.AuthorizationCode{
		Code: "version-bound-code", SubjectID: "123e4567-e89b-12d3-a456-426614174104",
		SecurityVersion: 42, ClientID: "client", RedirectURI: "https://client.example.test/callback",
		Scopes: []string{oidc.ScopeOpenID}, AuthenticatedAt: now, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	require.NoError(t, state.AuthorizationCodes().Save(t.Context(), record))
	consumed, err := state.AuthorizationCodes().Consume(t.Context(), record.Code)
	require.NoError(t, err)
	require.Equal(t, record.SecurityVersion, consumed.SecurityVersion)
	require.Equal(t, record.SubjectID, consumed.SubjectID)
	require.Equal(t, record.ClientID, consumed.ClientID)
	_, err = state.AuthorizationCodes().Consume(t.Context(), record.Code)
	require.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)
}
