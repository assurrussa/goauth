package legacysession

import (
	"context"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
)

type Adapter[T any] struct {
	store *session.Store
	key   string
}

func New[T any](store *session.Store, key string) (*Adapter[T], error) {
	switch {
	case store == nil:
		return nil, errors.New("store is required")
	case key == "":
		return nil, errors.New("key is required")
	}

	return &Adapter[T]{
		store: store,
		key:   key,
	}, nil
}

func Must[T any](store *session.Store, key string) *Adapter[T] {
	adapter, err := New[T](store, key)
	if err != nil {
		panic(fmt.Errorf("fatal legacy session adapter: %w", err))
	}

	return adapter
}

func (a *Adapter[T]) Put(c fiber.Ctx, payload T) (string, error) {
	sess, err := a.store.Get(c)
	if err != nil {
		return "", err
	}
	defer sess.Release()

	sessionID, err := ensureSessionID(sess)
	if err != nil {
		return "", err
	}

	sess.Set(a.key, payload)
	if err := sess.Save(); err != nil {
		return "", err
	}

	return sessionID, nil
}

func (a *Adapter[T]) Get(c fiber.Ctx) (string, T, bool, error) {
	var zero T

	sess, err := a.store.Get(c)
	if err != nil {
		return "", zero, false, err
	}
	defer sess.Release()

	sessionID := sess.ID()
	payload, ok := sess.Get(a.key).(T)
	if !ok {
		return sessionID, zero, false, nil
	}

	return sessionID, payload, true, nil
}

func (a *Adapter[T]) GetByID(ctx context.Context, sessionID string) (T, bool, error) {
	var zero T

	sess, err := a.store.GetByID(ctx, sessionID)
	if err != nil {
		return zero, false, err
	}
	defer sess.Release()

	payload, ok := sess.Get(a.key).(T)
	if !ok {
		return zero, false, nil
	}

	return payload, true, nil
}

func (a *Adapter[T]) Delete(c fiber.Ctx) error {
	sess, err := a.store.Get(c)
	if err != nil {
		return err
	}
	defer sess.Release()

	sess.Delete(a.key)
	return sess.Save()
}

func ensureSessionID(sess *session.Session) (string, error) {
	sessionID := sess.ID()
	if sessionID != "" {
		return sessionID, nil
	}

	if err := sess.Regenerate(); err != nil {
		return "", err
	}

	return sess.ID(), nil
}
