package postgres

import (
	"errors"

	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/oidc/provider"
)

// OIDCProvider assembles the optional provider against canonical Account
// claims and the Runtime's digest-only refresh-token store. The caller owns
// client/signing-key stores and supplies atomic request/code stores, normally
// from the Redis adapter.
func (r *Runtime) OIDCProvider(options provider.Options) (*provider.Service, error) {
	if r == nil || r.store == nil || r.oidcRefreshTokens == nil {
		return nil, errors.New("PostgreSQL Runtime is not initialized")
	}
	options.Claims = r
	options.RefreshTokens = r.oidcRefreshTokens

	return provider.New(options)
}

var _ oidc.ClaimsResolver = (*Runtime)(nil)
