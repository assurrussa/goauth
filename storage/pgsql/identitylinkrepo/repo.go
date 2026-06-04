package identitylinkrepo

import (
	"errors"
	"fmt"

	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

type Repo struct {
	pgsql outbox.StoragePgsqlClient
}

func New(db outbox.StoragePgsqlClient) (*Repo, error) {
	if db == nil {
		return nil, errors.New("pgsql client is required")
	}

	return &Repo{pgsql: db}, nil
}

func Must(db outbox.StoragePgsqlClient) *Repo {
	repo, err := New(db)
	if err != nil {
		panic(fmt.Errorf("fatal identity link repo: %w", err))
	}

	return repo
}
