package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
)

func (s *Service) signAccessToken(
	ctx context.Context,
	account goauth.Account,
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
			Subject:   account.Subject.ID.String(),
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
	account goauth.Account,
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
			Subject:   account.Subject.ID.String(),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	if oidc.HasScope(scopes, oidc.ScopeEmail) && account.PrimaryEmail.DisplayValue != "" {
		claims.Email = account.PrimaryEmail.DisplayValue
		verified := account.EmailVerified()
		claims.EmailVerified = &verified
	}
	if oidc.HasScope(scopes, oidc.ScopeProfile) {
		claims.Name = account.Profile.DisplayName
		claims.PreferredUsername = account.Profile.Username
	}

	return s.signToken(key, claims, "JWT")
}

func (s *Service) signToken(key oidc.SigningKey, claims jwt.Claims, typ string) (string, error) {
	if err := validateSigningKey(key); err != nil {
		return "", err
	}
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

func validateSigningKey(key oidc.SigningKey) error {
	if err := oidc.ValidateRSAPublicKey(key.PublicKey); err != nil {
		return err
	}
	if key.PrivateKey == nil || key.PrivateKey.D == nil || key.PrivateKey.D.Sign() <= 0 {
		return errors.New("invalid rsa private key")
	}
	if err := oidc.ValidateRSAPublicKey(&key.PrivateKey.PublicKey); err != nil {
		return err
	}
	if !key.PublicKey.Equal(&key.PrivateKey.PublicKey) {
		return errors.New("rsa private and public keys do not match")
	}
	for _, prime := range key.PrivateKey.Primes {
		if prime == nil || prime.Sign() <= 0 {
			return errors.New("invalid rsa private key prime")
		}
	}
	return key.PrivateKey.Validate()
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
			if err := oidc.ValidateRSAPublicKey(key.PublicKey); err != nil {
				return nil, err
			}
			return key.PublicKey, nil
		}

		key, err := s.keys.Get(ctx, kid)
		if err != nil {
			return nil, err
		}
		if err := oidc.ValidateRSAPublicKey(key.PublicKey); err != nil {
			return nil, err
		}

		return key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(s.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.now))
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, errors.New("token is invalid")
	}
	if claims.IssuedAt == nil {
		return nil, errors.New("token issued at is required")
	}

	return claims, nil
}
