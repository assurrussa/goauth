package goauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/oidc/provider"
	"github.com/assurrussa/goauth/postgres"
)

var _ oidc.SessionStateStore = (*postgres.SessionOIDCState)(nil)

var (
	_ = oidc.CanonicalIdentifiers{Version: 1, Login: "canonical", EmailAlias: "alias@example.test"}
	_ = oidc.SessionProjection{Identifiers: &oidc.CanonicalIdentifiers{Version: 1, Login: "canonical"}}
	_ = oidc.SessionUserInfo{Identifiers: &oidc.CanonicalIdentifiers{Version: 1, Login: "canonical"}}
)

var (
	_ func(*postgres.Runtime) (*postgres.SessionOIDCState, error)     = postgres.NewSessionOIDCState
	_ func(provider.SessionOptions) (*provider.SessionService, error) = provider.NewSessionBound
	_ func(
		*postgres.SessionOIDCState, context.Context,
	) (postgres.SessionOIDCCleanupResult, error) = (*postgres.SessionOIDCState).CleanupExpired
	_ func(
		*provider.SessionService, context.Context, oidc.SessionAuthorizeRequest, *oidc.BrowserSession,
	) (*oidc.AuthorizeResult, error) = (*provider.SessionService).Authorize
	_ func(
		*provider.SessionService, context.Context, string, *oidc.BrowserSession, string,
	) (*oidc.AuthorizeResult, error) = (*provider.SessionService).ContinueAuthorization
	_ func(
		*provider.SessionService, context.Context, oidc.TokenRequest,
	) (*oidc.TokenResponse, error) = (*provider.SessionService).ExchangeToken
	_ func(
		*provider.SessionService, context.Context, string,
	) (oidc.SessionUserInfo, error) = (*provider.SessionService).UserInfo
	_ func(
		*provider.SessionService, context.Context, oidc.RevokeRequest,
	) error = (*provider.SessionService).Revoke
	_ func(
		*provider.SessionService, context.Context,
	) oidc.SessionDiscoveryMetadata = (*provider.SessionService).Discovery
	_ func(
		*provider.SessionService, context.Context,
	) (oidc.JWKS, error) = (*provider.SessionService).JWKS
)

func TestSessionSurfaceKeepsLegacyUnkeyedLayouts(t *testing.T) {
	t.Helper()
	var z string
	// Additive strict types must not expand old structs and break these literals.
	type legacyRefresh oidc.RefreshToken
	type legacyRequest oidc.AuthorizationRequest
	type legacyCode oidc.AuthorizationCode
	type legacyClient oidc.Client
	_ = legacyRefresh{z, z, z, nil, 1, time.Time{}, time.Time{}, time.Time{}, nil}
	_ = legacyRequest{z, z, z, z, z, nil, z, z, time.Time{}, time.Time{}}
	_ = legacyCode{z, z, 1, z, z, nil, z, z, z, time.Time{}, time.Time{}, time.Time{}}
	_ = legacyClient{z, z, nil, nil, nil, z, true, true}
}
