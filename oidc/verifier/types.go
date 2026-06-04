package verifier

import (
	"context"
	"strings"
	"time"
)

type VerifiedAccessToken struct {
	Subject   string
	Issuer    string
	Audience  string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	KeyID     string
}

type contextKey string

//nolint:gosec // Static context key marker, not a credential.
const verifiedAccessTokenContextKey contextKey = "oidc.verified_access_token"

func WithVerifiedAccessToken(ctx context.Context, token VerifiedAccessToken) context.Context {
	return context.WithValue(ctx, verifiedAccessTokenContextKey, token)
}

func VerifiedAccessTokenFromContext(ctx context.Context) (VerifiedAccessToken, bool) {
	token, ok := ctx.Value(verifiedAccessTokenContextKey).(VerifiedAccessToken)
	return token, ok
}

func ExtractBearerToken(header string) string {
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}

	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}
