package oidc

import (
	"context"
	"errors"
	"time"

	authcore "github.com/assurrussa/goauth/core"
)

var (
	ErrAuthorizationRequestNotFound = errors.New("authorization request not found")
	ErrAuthorizationCodeNotFound    = errors.New("authorization code not found")
	ErrRefreshTokenNotFound         = errors.New("oidc refresh token not found")
)

type ClientStore interface {
	Get(ctx context.Context, clientID string) (Client, error)
}

type AuthorizationRequestStore interface {
	Save(ctx context.Context, request AuthorizationRequest) error
	Get(ctx context.Context, challenge string) (AuthorizationRequest, error)
	Delete(ctx context.Context, challenge string) error
}

type AuthorizationCodeStore interface {
	Save(ctx context.Context, code AuthorizationCode) error
	Get(ctx context.Context, code string) (AuthorizationCode, error)
	Delete(ctx context.Context, code string) error
}

type RefreshTokenStore interface {
	Save(ctx context.Context, token RefreshToken) error
	Get(ctx context.Context, token string) (RefreshToken, error)
	Revoke(ctx context.Context, token string, revokedAt time.Time) error
	Rotate(ctx context.Context, currentToken string, next RefreshToken, revokedAt time.Time) error
}

type TokenSigningKeyStore interface {
	Active(ctx context.Context) (SigningKey, error)
	Get(ctx context.Context, keyID string) (SigningKey, error)
	Public(ctx context.Context) ([]JWK, error)
}

type ClaimsResolver interface {
	Resolve(ctx context.Context, subjectID string) (authcore.Subject, error)
}
