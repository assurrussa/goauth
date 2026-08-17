package redis

import (
	"errors"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/assurrussa/goauth/internal/oidcstate"
	"github.com/assurrussa/goauth/oidc"
)

type OIDCConfig struct {
	Client *goredis.Client
	Prefix string
}

// OIDCState exposes atomic Redis-backed authorization request and code stores.
// Both one-time paths consume state with Redis GETDEL.
type OIDCState struct {
	requests oidc.AuthorizationRequestStore
	codes    oidc.AuthorizationCodeStore
}

func NewOIDCState(config OIDCConfig) (*OIDCState, error) {
	if config.Client == nil {
		return nil, errors.New("redis client is required")
	}
	prefix := strings.TrimSpace(config.Prefix)
	if prefix == "" {
		prefix = "goauth:"
	}

	return &OIDCState{
		requests: oidcstate.NewRequestStore(config.Client, prefix+"oidc:request:"),
		codes:    oidcstate.NewCodeStore(config.Client, prefix+"oidc:code:"),
	}, nil
}

func (s *OIDCState) AuthorizationRequests() oidc.AuthorizationRequestStore {
	if s == nil {
		return nil
	}

	return s.requests
}

func (s *OIDCState) AuthorizationCodes() oidc.AuthorizationCodeStore {
	if s == nil {
		return nil
	}

	return s.codes
}
