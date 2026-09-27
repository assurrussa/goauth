package oidclinkedsubject

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	oidcbearer "github.com/assurrussa/goauth/internal/legacy/http/fiber/oidcbearer"
	oidcctx "github.com/assurrussa/goauth/internal/legacy/http/oidcctx"
	"github.com/assurrussa/goauth/internal/legacy/sso"
	externalidentity "github.com/assurrussa/goauth/internal/legacy/sso/externalidentity"
	oidcverifier "github.com/assurrussa/goauth/oidc/verifier"
)

type accessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, rawToken string) (oidcverifier.VerifiedAccessToken, error)
}

type externalIdentityResolver interface {
	Resolve(ctx context.Context, accessToken string, verified oidcverifier.VerifiedAccessToken) (sso.ExternalIdentity, error)
}

type linkedIdentityResolver interface {
	Resolve(ctx context.Context, external sso.ExternalIdentity) (authcore.Subject, sso.IdentityProfile, error)
}

func New(
	verifier accessTokenVerifier,
	externalResolver externalIdentityResolver,
	linkedResolver linkedIdentityResolver,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		if verifier == nil || externalResolver == nil || linkedResolver == nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
		}

		accessToken := oidcverifier.ExtractBearerToken(c.Get(fiber.HeaderAuthorization))
		if accessToken == "" {
			return oidcbearer.WriteBearerError(c, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		}

		verified, err := verifier.VerifyAccessToken(c, accessToken)
		if err != nil {
			if hasMissingScopeError(err) {
				return oidcbearer.WriteBearerError(c, http.StatusForbidden, "insufficient_scope", err.Error())
			}

			return oidcbearer.WriteBearerError(c, http.StatusUnauthorized, "invalid_token", err.Error())
		}

		externalIdentity, err := externalResolver.Resolve(c, accessToken, verified)
		if err != nil {
			return oidcbearer.WriteBearerError(c, http.StatusForbidden, "access_denied", err.Error())
		}

		subject, profile, err := linkedResolver.Resolve(c, externalIdentity)
		if err != nil {
			if isControlledLinkError(err) {
				return oidcbearer.WriteBearerError(c, http.StatusForbidden, "access_denied", err.Error())
			}

			return oidcbearer.WriteBearerError(
				c,
				http.StatusInternalServerError,
				"server_error",
				"failed to resolve local identity",
			)
		}

		oidcctx.SetVerifiedAccessToken(c, verified)
		oidcctx.SetExternalIdentity(c, externalIdentity)
		oidcctx.SetLinkedSubject(c, subject)
		oidcctx.SetIdentityProfile(c, profile)
		return c.Next()
	}
}

func isControlledLinkError(err error) bool {
	return errors.Is(err, externalidentity.ErrEmailConflict) ||
		errors.Is(err, externalidentity.ErrEmailRequired)
}

func hasMissingScopeError(err error) bool {
	return strings.Contains(err.Error(), `required scope "`)
}
