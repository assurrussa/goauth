package oidc

import (
	"context"

	"github.com/gofiber/fiber/v3"

	authcore "github.com/assurrussa/goauth/core"
	oidcbearer "github.com/assurrussa/goauth/http/fiber/oidcbearer"
	oidclinkedsubject "github.com/assurrussa/goauth/http/fiber/oidclinkedsubject"
	oidcverifier "github.com/assurrussa/goauth/oidc/verifier"
	"github.com/assurrussa/goauth/sso"
)

type AccessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, rawToken string) (oidcverifier.VerifiedAccessToken, error)
}

type ExternalIdentityResolver interface {
	Resolve(ctx context.Context, accessToken string, verified oidcverifier.VerifiedAccessToken) (sso.ExternalIdentity, error)
}

type LinkedIdentityResolver interface {
	Resolve(ctx context.Context, external sso.ExternalIdentity) (authcore.Subject, sso.IdentityProfile, error)
}

func NewBearerMiddleware(verifier AccessTokenVerifier) fiber.Handler {
	return oidcbearer.New(verifier)
}

func NewLinkedSubjectMiddleware(
	verifier AccessTokenVerifier,
	externalResolver ExternalIdentityResolver,
	linkedResolver LinkedIdentityResolver,
) fiber.Handler {
	return oidclinkedsubject.New(verifier, externalResolver, linkedResolver)
}

func WriteBearerError(c fiber.Ctx, status int, code, description string) error {
	return oidcbearer.WriteBearerError(c, status, code, description)
}
