package sso

import (
	"context"
	"errors"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/oidc"
)

var ErrIdentityLinkNotFound = errors.New("identity link not found")

type Provider interface {
	Enabled() bool
	Discovery(ctx context.Context) oidc.DiscoveryMetadata
	JWKS(ctx context.Context) (oidc.JWKS, error)
	Authorize(ctx context.Context, req oidc.AuthorizeRequest, current *oidc.AuthenticatedSubject) (*oidc.AuthorizeResult, error)
	ContinueAuthorization(
		ctx context.Context,
		challenge string,
		current *oidc.AuthenticatedSubject,
	) (*oidc.AuthorizeResult, error)
	ExchangeToken(ctx context.Context, req oidc.TokenRequest) (*oidc.TokenResponse, error)
	Revoke(ctx context.Context, req oidc.RevokeRequest) error
	UserInfo(ctx context.Context, accessToken string) (oidc.UserInfo, error)
}

type LinkStore interface {
	GetByExternalSubject(ctx context.Context, issuer, externalSub string) (IdentityLink, error)
	ListBySubject(ctx context.Context, subjectID authcore.SubjectID) ([]IdentityLink, error)
	Upsert(ctx context.Context, link IdentityLink) error
	Delete(ctx context.Context, subjectID authcore.SubjectID, issuer, externalSub string) error
}
