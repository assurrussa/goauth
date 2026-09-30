package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/assurrussa/goauth"
)

var (
	ErrAuthorizationRequestNotFound = errors.New("authorization request not found")
	ErrAuthorizationCodeNotFound    = errors.New("authorization code not found")
	ErrRefreshTokenNotFound         = errors.New("oidc refresh token not found")
	ErrRefreshTokenReplay           = errors.New("oidc refresh token replay detected")
)

type ClientStore interface {
	Get(ctx context.Context, clientID string) (Client, error)
}

// ClientSecretVerifier authenticates a client secret against host-managed storage.
// A configured verifier is authoritative; any error denies authentication.
type ClientSecretVerifier interface {
	VerifyClientSecret(ctx context.Context, clientID, secret string) error
}

// ClientSecretVerifierFunc adapts a function to ClientSecretVerifier.
type ClientSecretVerifierFunc func(ctx context.Context, clientID, secret string) error

func (f ClientSecretVerifierFunc) VerifyClientSecret(ctx context.Context, clientID, secret string) error {
	return f(ctx, clientID, secret)
}

type AuthorizationRequestStore interface {
	Save(ctx context.Context, request AuthorizationRequest) error
	Get(ctx context.Context, challenge string) (AuthorizationRequest, error)
	Consume(ctx context.Context, challenge string) (AuthorizationRequest, error)
}

type AuthorizationCodeStore interface {
	Save(ctx context.Context, code AuthorizationCode) error
	Consume(ctx context.Context, code string) (AuthorizationCode, error)
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
	Resolve(ctx context.Context, subjectID string) (goauth.Account, error)
}
