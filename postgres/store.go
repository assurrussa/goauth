package postgres

import (
	"database/sql"
	"errors"

	"github.com/assurrussa/goauth"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("PostgreSQL database is required")
	}

	return &Store{db: db}, nil
}

var _ goauth.RuntimeStore = (*Store)(nil)
