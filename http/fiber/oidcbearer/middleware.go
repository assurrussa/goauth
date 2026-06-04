package oidcbearer

import (
	"context"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3"

	oidcctx "github.com/assurrussa/goauth/http/oidcctx"
	oidcverifier "github.com/assurrussa/goauth/oidc/verifier"
)

type accessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, rawToken string) (oidcverifier.VerifiedAccessToken, error)
}

func New(verifier accessTokenVerifier) fiber.Handler {
	return func(c fiber.Ctx) error {
		if verifier == nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "server_error"})
		}

		accessToken := oidcverifier.ExtractBearerToken(c.Get(fiber.HeaderAuthorization))
		if accessToken == "" {
			return WriteBearerError(c, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		}

		verified, err := verifier.VerifyAccessToken(c, accessToken)
		if err != nil {
			if strings.Contains(err.Error(), `required scope "`) {
				return WriteBearerError(c, http.StatusForbidden, "insufficient_scope", err.Error())
			}

			return WriteBearerError(c, http.StatusUnauthorized, "invalid_token", err.Error())
		}

		oidcctx.SetVerifiedAccessToken(c, verified)
		return c.Next()
	}
}

func WriteBearerError(c fiber.Ctx, status int, code, description string) error {
	if strings.TrimSpace(description) == "" {
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer error="`+code+`"`)
	} else {
		c.Set(
			fiber.HeaderWWWAuthenticate,
			`Bearer error="`+code+`", error_description="`+description+`"`,
		)
	}

	return c.Status(status).JSON(fiber.Map{
		"error":             code,
		"error_description": description,
	})
}
