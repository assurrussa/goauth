package adminsession

import (
	"github.com/gofiber/fiber/v3/middleware/session"

	legacysession "github.com/assurrussa/goauth/http/fiber/legacysession"
)

type LegacySessionAdapter[T any] = legacysession.Adapter[T]

func NewLegacySessionAdapter[T any](store *session.Store, key string) (*LegacySessionAdapter[T], error) {
	return legacysession.New[T](store, key)
}

func MustLegacySessionAdapter[T any](store *session.Store, key string) *LegacySessionAdapter[T] {
	return legacysession.Must[T](store, key)
}
