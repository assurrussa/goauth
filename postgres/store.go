package postgres

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/assurrussa/goauth"
)

type Store struct {
	db *sql.DB

	rateMu     sync.Mutex
	rateEvents map[string][]time.Time
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("PostgreSQL database is required")
	}

	return &Store{
		db:         db,
		rateEvents: make(map[string][]time.Time),
	}, nil
}

var _ goauth.RuntimeStore = (*Store)(nil)
