package oidcstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/assurrussa/goauth/oidc"
)

type RedisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
}

type RequestStore struct {
	client RedisClient
	prefix string
}

type CodeStore struct {
	client RedisClient
	prefix string
}

func NewRequestStore(client RedisClient, prefix string) *RequestStore {
	if prefix == "" {
		prefix = "oidc:authreq:"
	}

	return &RequestStore{client: client, prefix: prefix}
}

func NewCodeStore(client RedisClient, prefix string) *CodeStore {
	if prefix == "" {
		prefix = "oidc:authcode:"
	}

	return &CodeStore{client: client, prefix: prefix}
}

func (s *RequestStore) Save(ctx context.Context, request oidc.AuthorizationRequest) error {
	if s == nil || s.client == nil {
		return errors.New("redis request store is not configured")
	}

	return saveJSON(ctx, s.client, s.key(request.Challenge), request.ExpiresAt, request)
}

func (s *RequestStore) Get(ctx context.Context, challenge string) (oidc.AuthorizationRequest, error) {
	if s == nil || s.client == nil {
		return oidc.AuthorizationRequest{}, errors.New("redis request store is not configured")
	}

	var request oidc.AuthorizationRequest
	err := loadJSON(ctx, s.client, s.key(challenge), &request)
	if errors.Is(err, redis.Nil) {
		return oidc.AuthorizationRequest{}, oidc.ErrAuthorizationRequestNotFound
	}
	if err != nil {
		return oidc.AuthorizationRequest{}, err
	}

	return request, nil
}

func (s *RequestStore) Delete(ctx context.Context, challenge string) error {
	if s == nil || s.client == nil {
		return errors.New("redis request store is not configured")
	}

	return s.client.Del(ctx, s.key(challenge)).Err()
}

func (s *RequestStore) key(challenge string) string {
	return s.prefix + strings.TrimSpace(challenge)
}

func (s *CodeStore) Save(ctx context.Context, code oidc.AuthorizationCode) error {
	if s == nil || s.client == nil {
		return errors.New("redis code store is not configured")
	}

	return saveJSON(ctx, s.client, s.key(code.Code), code.ExpiresAt, code)
}

func (s *CodeStore) Get(ctx context.Context, code string) (oidc.AuthorizationCode, error) {
	if s == nil || s.client == nil {
		return oidc.AuthorizationCode{}, errors.New("redis code store is not configured")
	}

	var record oidc.AuthorizationCode
	err := loadJSON(ctx, s.client, s.key(code), &record)
	if errors.Is(err, redis.Nil) {
		return oidc.AuthorizationCode{}, oidc.ErrAuthorizationCodeNotFound
	}
	if err != nil {
		return oidc.AuthorizationCode{}, err
	}

	return record, nil
}

func (s *CodeStore) Delete(ctx context.Context, code string) error {
	if s == nil || s.client == nil {
		return errors.New("redis code store is not configured")
	}

	return s.client.Del(ctx, s.key(code)).Err()
}

func (s *CodeStore) key(code string) string {
	return s.prefix + strings.TrimSpace(code)
}

func saveJSON(ctx context.Context, client RedisClient, key string, expiresAt time.Time, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal redis oidc state: %w", err)
	}

	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = time.Second
	}

	if err := client.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("set redis oidc state: %w", err)
	}

	return nil
}

func loadJSON(ctx context.Context, client RedisClient, key string, target any) error {
	raw, err := client.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("unmarshal redis oidc state: %w", err)
	}

	return nil
}
