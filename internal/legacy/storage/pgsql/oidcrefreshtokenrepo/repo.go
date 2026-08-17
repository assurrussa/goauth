package oidcrefreshtokenrepo

import (
	"fmt"

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

//go:generate options-gen -out-filename=repo_options.gen.go -from-struct=Options
type Options struct {
	pgsql      outbox.StoragePgsqlClient    `option:"mandatory" validate:"required"`
	trxManager outbox.StoragePgsqlTxManager `option:"mandatory" validate:"required"`
}

type Repo struct {
	Options
}

func Must(opts Options) *Repo {
	repo, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("fatal oidc refresh token repo: %w", err))
	}

	return repo
}

func New(opts Options) (*Repo, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}

	return &Repo{Options: opts}, nil
}
