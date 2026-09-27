package oidcctx

import (
	"context"

	"github.com/gofiber/fiber/v3"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/sso"
	oidcverifier "github.com/assurrussa/goauth/oidc/verifier"
)

//nolint:gosec // Static locals key, not a credential.
const VerifiedAccessTokenCtxKey = "oidc.verified_access_token"

const ExternalIdentityCtxKey = "oidc.external_identity"

const IdentityProfileCtxKey = "oidc.identity_profile"

const LinkedSubjectCtxKey = "oidc.linked_subject"

type contextKey string

const (
	externalIdentityContextKey contextKey = "oidc.external_identity"
	identityProfileContextKey  contextKey = "oidc.identity_profile"
	linkedSubjectContextKey    contextKey = "oidc.linked_subject"
)

func SetVerifiedAccessToken(c fiber.Ctx, token oidcverifier.VerifiedAccessToken) {
	c.Locals(VerifiedAccessTokenCtxKey, token)
	c.SetContext(oidcverifier.WithVerifiedAccessToken(c.Context(), token))
}

func GetVerifiedAccessToken(c fiber.Ctx) (oidcverifier.VerifiedAccessToken, bool) {
	token, ok := c.Locals(VerifiedAccessTokenCtxKey).(oidcverifier.VerifiedAccessToken)
	if ok {
		return token, true
	}

	return oidcverifier.VerifiedAccessTokenFromContext(c.Context())
}

func SetExternalIdentity(c fiber.Ctx, identity sso.ExternalIdentity) {
	c.Locals(ExternalIdentityCtxKey, identity)
	c.SetContext(context.WithValue(c.Context(), externalIdentityContextKey, identity))
}

func GetExternalIdentity(c fiber.Ctx) (sso.ExternalIdentity, bool) {
	identity, ok := c.Locals(ExternalIdentityCtxKey).(sso.ExternalIdentity)
	if ok {
		return identity, true
	}

	identity, ok = c.Context().Value(externalIdentityContextKey).(sso.ExternalIdentity)
	return identity, ok
}

func SetIdentityProfile(c fiber.Ctx, profile sso.IdentityProfile) {
	c.Locals(IdentityProfileCtxKey, profile)
	c.SetContext(context.WithValue(c.Context(), identityProfileContextKey, profile))
}

func GetIdentityProfile(c fiber.Ctx) (sso.IdentityProfile, bool) {
	profile, ok := c.Locals(IdentityProfileCtxKey).(sso.IdentityProfile)
	if ok {
		return profile, true
	}

	profile, ok = c.Context().Value(identityProfileContextKey).(sso.IdentityProfile)
	return profile, ok
}

func SetLinkedSubject(c fiber.Ctx, subject authcore.Subject) {
	c.Locals(LinkedSubjectCtxKey, subject)
	c.SetContext(context.WithValue(c.Context(), linkedSubjectContextKey, subject))
}

func GetLinkedSubject(c fiber.Ctx) (authcore.Subject, bool) {
	subject, ok := c.Locals(LinkedSubjectCtxKey).(authcore.Subject)
	if ok {
		return subject, true
	}

	subject, ok = c.Context().Value(linkedSubjectContextKey).(authcore.Subject)
	return subject, ok
}
