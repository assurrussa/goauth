package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	authcore "github.com/assurrussa/goauth/core"
)

var (
	ErrSessionExpired = errors.New("session expired")
	ErrSessionRevoked = errors.New("session revoked")
)

type Store interface {
	Save(ctx context.Context, session authcore.AuthSession, payload []byte) error
	Get(ctx context.Context, token string) (authcore.AuthSession, []byte, error)
	Delete(ctx context.Context, token string) error
}

type Options[T any] struct {
	Store Store
	Now   func() time.Time
}

type Record[T any] struct {
	Session authcore.AuthSession
	Payload T
}

type Service[T any] struct {
	store Store
	now   func() time.Time
}

func New[T any](opts Options[T]) (*Service[T], error) {
	if opts.Store == nil {
		return nil, errors.New("store is required")
	}

	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}

	return &Service[T]{
		store: opts.Store,
		now:   now,
	}, nil
}

func Must[T any](opts Options[T]) *Service[T] {
	svc, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("fatal session runtime: %w", err))
	}

	return svc
}

func (s *Service[T]) Save(ctx context.Context, session authcore.AuthSession, payload T) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal session payload: %w", err)
	}

	return s.store.Save(ctx, session, raw)
}

func (s *Service[T]) Load(ctx context.Context, token string) (Record[T], error) {
	session, rawPayload, err := s.store.Get(ctx, token)
	if err != nil {
		return Record[T]{}, err
	}

	now := s.now()
	switch {
	case !session.ExpiresAt.IsZero() && session.ExpiresAt.Before(now):
		if err := s.store.Delete(ctx, token); err != nil {
			return Record[T]{}, fmt.Errorf("delete expired session: %w", err)
		}
		return Record[T]{}, ErrSessionExpired
	case session.RevokedAt != nil:
		if err := s.store.Delete(ctx, token); err != nil {
			return Record[T]{}, fmt.Errorf("delete revoked session: %w", err)
		}
		return Record[T]{}, ErrSessionRevoked
	}

	var payload T
	if len(rawPayload) != 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return Record[T]{}, fmt.Errorf("unmarshal session payload: %w", err)
		}
	}

	return Record[T]{
		Session: session,
		Payload: payload,
	}, nil
}

func (s *Service[T]) Delete(ctx context.Context, token string) error {
	return s.store.Delete(ctx, token)
}
