package redis_test

import (
	"testing"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	goauthredis "github.com/assurrussa/goauth/redis"
)

func TestOIDCStateConstructorAndNilAccessors(t *testing.T) {
	t.Parallel()
	_, err := goauthredis.NewOIDCState(goauthredis.OIDCConfig{})
	require.EqualError(t, err, "redis client is required")

	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	t.Cleanup(func() { _ = client.Close() })
	state, err := goauthredis.NewOIDCState(goauthredis.OIDCConfig{Client: client})
	require.NoError(t, err)
	require.NotNil(t, state.AuthorizationRequests())
	require.NotNil(t, state.AuthorizationCodes())

	var missing *goauthredis.OIDCState
	require.Nil(t, missing.AuthorizationRequests())
	require.Nil(t, missing.AuthorizationCodes())
}
