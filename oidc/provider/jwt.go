package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/oidc"
)

func (s *Service) signAccessToken(
	ctx context.Context,
	subject authcore.Subject,
	clientID string,
	scopes []string,
) (string, error) {
	key, err := s.keys.Active(ctx)
	if err != nil {
		return "", fmt.Errorf("get active signing key: %w", err)
	}

	now := s.now()
	claims := accessTokenClaims{
		ClientID: clientID,
		Scope:    oidc.ScopeString(scopes),
		TokenUse: tokenUseAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject.CanonicalID(),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	return s.signToken(key, claims, "at+jwt")
}

func (s *Service) signIDToken(
	ctx context.Context,
	subject authcore.Subject,
	clientID string,
	scopes []string,
	authenticatedAt time.Time,
	nonce string,
) (string, error) {
	key, err := s.keys.Active(ctx)
	if err != nil {
		return "", fmt.Errorf("get active signing key: %w", err)
	}

	now := s.now()
	claims := idTokenClaims{
		Nonce:    nonce,
		TokenUse: tokenUseID,
		AuthTime: authenticatedAt.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject.CanonicalID(),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	if oidc.HasScope(scopes, oidc.ScopeEmail) && subject.Email != "" {
		claims.Email = subject.Email
		verified := true
		claims.EmailVerified = &verified
	}
	if oidc.HasScope(scopes, oidc.ScopeProfile) {
		claims.Name = subject.Name
		claims.PreferredUsername = subject.Username
	}

	return s.signToken(key, claims, "JWT")
}

func (s *Service) signToken(key oidc.SigningKey, claims jwt.Claims, typ string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.ID
	if typ != "" {
		token.Header["typ"] = typ
	}

	signed, err := token.SignedString(key.PrivateKey)
	if err != nil {
		return "", err
	}

	return signed, nil
}

func (s *Service) parseAccessToken(ctx context.Context, token string) (*accessTokenClaims, error) {
	claims := &accessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			key, err := s.keys.Active(ctx)
			if err != nil {
				return nil, err
			}
			return key.PublicKey, nil
		}

		key, err := s.keys.Get(ctx, kid)
		if err != nil {
			return nil, err
		}

		return key.PublicKey, nil
	}, jwt.WithIssuer(s.issuer))
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, errors.New("token is invalid")
	}

	return claims, nil
}
