//nolint:testpackage // Tests exercise same-package Redis helpers and sentinel mappings directly.
package oidcstate

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestRequestStoreRoundTrip(t *testing.T) {
	t.Parallel()

	client := newFakeRedisClient()
	store := NewRequestStore(client, "test:req:")
	now := time.Now().UTC()

	err := store.Save(context.Background(), oidc.AuthorizationRequest{
		Challenge:   "challenge-1",
		ClientID:    "pet-app",
		RedirectURI: "https://client.local/callback",
		Scopes:      []string{oidc.ScopeOpenID, oidc.ScopeProfile},
		RequestedAt: now,
		ExpiresAt:   now.Add(5 * time.Minute),
	})
	require.NoError(t, err)
	require.Positive(t, client.ttls["test:req:challenge-1"])

	record, err := store.Get(context.Background(), "challenge-1")
	require.NoError(t, err)
	require.Equal(t, "pet-app", record.ClientID)
	require.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeProfile}, record.Scopes)

	record, err = store.Consume(context.Background(), "challenge-1")
	require.NoError(t, err)
	require.Equal(t, "pet-app", record.ClientID)

	_, err = store.Get(context.Background(), "challenge-1")
	require.ErrorIs(t, err, oidc.ErrAuthorizationRequestNotFound)
}

func TestCodeStoreRoundTrip(t *testing.T) {
	t.Parallel()

	client := newFakeRedisClient()
	store := NewCodeStore(client, "test:code:")
	now := time.Now().UTC()

	err := store.Save(context.Background(), oidc.AuthorizationCode{
		Code:            "code-1",
		SubjectID:       "123e4567-e89b-12d3-a456-426614174104",
		ClientID:        "pet-app",
		RedirectURI:     "https://client.local/callback",
		Scopes:          []string{oidc.ScopeOpenID},
		AuthenticatedAt: now,
		CreatedAt:       now,
		ExpiresAt:       now.Add(2 * time.Minute),
	})
	require.NoError(t, err)

	record, err := store.Consume(context.Background(), "code-1")
	require.NoError(t, err)
	require.Equal(t, "123e4567-e89b-12d3-a456-426614174104", record.SubjectID)
	require.Equal(t, "pet-app", record.ClientID)

	_, err = store.Consume(context.Background(), "code-1")
	require.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)
}

type fakeRedisClient struct {
	values map[string]string
	ttls   map[string]time.Duration
}

func newFakeRedisClient() *fakeRedisClient {
	return &fakeRedisClient{
		values: make(map[string]string),
		ttls:   make(map[string]time.Duration),
	}
}

func (c *fakeRedisClient) Get(_ context.Context, key string) *redis.StringCmd {
	value, ok := c.values[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}

	return redis.NewStringResult(value, nil)
}

func (c *fakeRedisClient) GetDel(_ context.Context, key string) *redis.StringCmd {
	value, ok := c.values[key]
	if !ok {
		return redis.NewStringResult("", redis.Nil)
	}
	delete(c.values, key)
	delete(c.ttls, key)

	return redis.NewStringResult(value, nil)
}

func (c *fakeRedisClient) Set(_ context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	switch typed := value.(type) {
	case []byte:
		c.values[key] = string(typed)
	case string:
		c.values[key] = typed
	default:
		c.values[key] = ""
	}
	c.ttls[key] = expiration

	return redis.NewStatusResult("OK", nil)
}

func (c *fakeRedisClient) Del(_ context.Context, keys ...string) *redis.IntCmd {
	var deleted int64
	for _, key := range keys {
		if _, ok := c.values[key]; ok {
			delete(c.values, key)
			delete(c.ttls, key)
			deleted++
		}
	}

	return redis.NewIntResult(deleted, nil)
}
