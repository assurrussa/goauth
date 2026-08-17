//go:build integration

package redis_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
	goauthredis "github.com/assurrussa/goauth/redis"
)

func TestRedisAuthorizationCodeGETDELIsAtomic(t *testing.T) {
	client := integrationRedis(t)
	state, err := goauthredis.NewOIDCState(goauthredis.OIDCConfig{Client: client, Prefix: "integration:"})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, state.AuthorizationCodes().Save(context.Background(), oidc.AuthorizationCode{
		Code:        "concurrent-code",
		SubjectID:   "123e4567-e89b-12d3-a456-426614174104",
		ClientID:    "client",
		RedirectURI: "https://client.example.test/callback",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Minute),
	}))

	const consumers = 32
	var successes atomic.Int64
	var missing atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range consumers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := state.AuthorizationCodes().Consume(context.Background(), "concurrent-code")
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, oidc.ErrAuthorizationCodeNotFound) {
				missing.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, consumers-1, missing.Load())
}

func TestRedisAuthorizationChallengeGETDELIsAtomic(t *testing.T) {
	client := integrationRedis(t)
	state, err := goauthredis.NewOIDCState(goauthredis.OIDCConfig{Client: client, Prefix: "integration:"})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, state.AuthorizationRequests().Save(context.Background(), oidc.AuthorizationRequest{
		Challenge:   "concurrent-challenge",
		ClientID:    "client",
		RedirectURI: "https://client.example.test/callback",
		RequestedAt: now,
		ExpiresAt:   now.Add(time.Minute),
	}))

	const consumers = 32
	var successes atomic.Int64
	var missing atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range consumers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := state.AuthorizationRequests().Consume(context.Background(), "concurrent-challenge")
			if err == nil {
				successes.Add(1)
			} else if errors.Is(err, oidc.ErrAuthorizationRequestNotFound) {
				missing.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, consumers-1, missing.Load())
}

func integrationRedis(t *testing.T) *goredis.Client {
	t.Helper()
	address := os.Getenv("GOAUTH_TEST_REDIS_ADDRESS")
	if address == "" {
		t.Skip("GOAUTH_TEST_REDIS_ADDRESS is not configured")
	}
	client := goredis.NewClient(&goredis.Options{Addr: address})
	require.NoError(t, client.Ping(context.Background()).Err())
	require.NoError(t, client.FlushDB(context.Background()).Err())
	t.Cleanup(func() { _ = client.Close() })

	return client
}
