package goauth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SigningConfig struct {
	Issuer   string
	Audience string
	Keys     KeyRing
}

type jwtIssuer struct {
	config SigningConfig
	now    func() time.Time
}

var reservedAccessTokenClaims = map[string]struct{}{
	"aud": {}, "exp": {}, "iat": {}, "iss": {}, "jti": {}, "nbf": {},
	"realm": {}, "scope": {}, "sid": {}, "sub": {}, "sv": {},
}

func newJWTIssuer(config SigningConfig, now func() time.Time) (*jwtIssuer, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.Audience = strings.TrimSpace(config.Audience)
	if config.Issuer == "" || config.Audience == "" {
		return nil, errors.New("JWT issuer and audience are required")
	}
	if _, err := config.Keys.Active(); err != nil {
		return nil, fmt.Errorf("validate JWT keys: %w", err)
	}
	if now == nil {
		now = time.Now
	}

	return &jwtIssuer{config: config, now: now}, nil
}

func (i *jwtIssuer) Sign(
	ctx context.Context,
	account Account,
	session Session,
	expiresAt time.Time,
	enricher ClaimsEnricher,
) (string, error) {
	now := i.now().UTC()
	claims := map[string]any{
		"iss":   i.config.Issuer,
		"aud":   i.config.Audience,
		"sub":   account.Subject.ID.String(),
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   expiresAt.Unix(),
		"jti":   session.ID + ":access:" + strconv.FormatInt(now.UnixNano(), 10),
		"sid":   session.ID,
		"realm": string(session.Realm),
		"scope": string(session.Scope),
		"sv":    account.Subject.SecurityVersion,
	}
	if enricher != nil {
		extraClaims := make(map[string]any)
		if err := enricher.EnrichClaims(ctx, session.Realm, account, extraClaims); err != nil {
			return "", fmt.Errorf("enrich access claims: %w", err)
		}
		for name, value := range extraClaims {
			if _, reserved := reservedAccessTokenClaims[name]; reserved {
				return "", fmt.Errorf("%w: %s", ErrReservedAccessTokenClaim, name)
			}
			claims[name] = value
		}
	}

	key, err := i.config.Keys.Active()
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	token.Header["kid"] = key.ID
	signed, err := token.SignedString(key.Material)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return signed, nil
}

func (i *jwtIssuer) Verify(raw string) (AuthContext, error) {
	parsed, err := jwt.Parse(
		raw,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, ErrInvalidToken
			}
			keyID, _ := token.Header["kid"].(string)
			key, err := i.config.Keys.Get(keyID)
			if err != nil {
				return nil, ErrInvalidToken
			}
			return key.Material, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(i.config.Issuer),
		jwt.WithAudience(i.config.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(i.now),
	)
	if err != nil || !parsed.Valid {
		return AuthContext{}, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return AuthContext{}, ErrInvalidToken
	}
	subjectValue, err := claims.GetSubject()
	if err != nil {
		return AuthContext{}, ErrInvalidToken
	}
	subjectID, err := ParseSubjectID(subjectValue)
	if err != nil {
		return AuthContext{}, ErrInvalidToken
	}
	realm, ok := claims["realm"].(string)
	if !ok || Realm(realm).Validate() != nil {
		return AuthContext{}, ErrInvalidToken
	}
	scope, ok := claims["scope"].(string)
	if !ok || (SessionScope(scope) != SessionScopeAuthenticated && SessionScope(scope) != SessionScopeConfirmation) {
		return AuthContext{}, ErrInvalidToken
	}
	sessionID, ok := claims["sid"].(string)
	if !ok || strings.TrimSpace(sessionID) == "" {
		return AuthContext{}, ErrInvalidToken
	}
	securityVersion, ok := numericClaim(claims["sv"])
	if !ok || securityVersion < 1 {
		return AuthContext{}, ErrInvalidToken
	}
	values := make(map[string]any, len(claims))
	for key, value := range claims {
		values[key] = value
	}

	return AuthContext{
		SubjectID:       subjectID,
		Realm:           Realm(realm),
		Scope:           SessionScope(scope),
		SessionID:       sessionID,
		SecurityVersion: securityVersion,
		Claims:          values,
	}, nil
}

func numericClaim(value any) (int64, bool) {
	typed, ok := value.(float64)
	return int64(typed), ok && typed == float64(int64(typed))
}
