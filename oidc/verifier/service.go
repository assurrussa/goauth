//nolint:tagliatelle // Verifier validates JWT access tokens and uses protocol snake_case claims.
package verifier

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/assurrussa/goauth/oidc"
)

const (
	defaultHTTPTimeout = 5 * time.Second
	defaultCacheTTL    = 5 * time.Minute
)

var errUnknownKeyID = errors.New("oidc verifier key id was not found in jwks")

type Options struct {
	Issuer         string
	Audience       string
	RequiredScopes []string
	HTTPClient     *http.Client
	CacheTTL       time.Duration
	Now            func() time.Time
}

type Service struct {
	issuer         string
	audience       string
	requiredScopes []string
	httpClient     *http.Client
	cacheTTL       time.Duration
	now            func() time.Time

	mu               sync.RWMutex
	discovery        oidc.DiscoveryMetadata
	discoveryFetched time.Time
	jwks             map[string]*rsa.PublicKey
	jwksFetched      time.Time
}

type accessTokenClaims struct {
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	TokenUse string `json:"token_use"`
	jwt.RegisteredClaims
}

func New(opts Options) (*Service, error) {
	issuer := strings.TrimRight(strings.TrimSpace(opts.Issuer), "/")
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	audience := strings.TrimSpace(opts.Audience)
	if audience == "" {
		return nil, errors.New("audience is required")
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}

	cacheTTL := opts.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultCacheTTL
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		issuer:         issuer,
		audience:       audience,
		requiredScopes: oidc.NormalizeScopes(opts.RequiredScopes),
		httpClient:     httpClient,
		cacheTTL:       cacheTTL,
		now:            now,
		jwks:           make(map[string]*rsa.PublicKey),
	}, nil
}

func (s *Service) VerifyAccessToken(ctx context.Context, rawToken string) (VerifiedAccessToken, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return VerifiedAccessToken{}, errors.New("access token is required")
	}

	if err := s.ensureJWKS(ctx, false); err != nil {
		return VerifiedAccessToken{}, err
	}

	claims, keyID, err := s.parseAccessToken(rawToken)
	if errors.Is(err, errUnknownKeyID) {
		if refreshErr := s.ensureJWKS(ctx, true); refreshErr != nil {
			return VerifiedAccessToken{}, refreshErr
		}
		claims, keyID, err = s.parseAccessToken(rawToken)
	}
	if err != nil {
		return VerifiedAccessToken{}, err
	}
	if claims.TokenUse != "" && claims.TokenUse != "access" {
		return VerifiedAccessToken{}, errors.New("token_use must be access")
	}

	scopes := oidc.ParseScope(claims.Scope)
	for _, requiredScope := range s.requiredScopes {
		if !oidc.HasScope(scopes, requiredScope) {
			return VerifiedAccessToken{}, fmt.Errorf("required scope %q is missing", requiredScope)
		}
	}

	verified := VerifiedAccessToken{
		Subject:  claims.Subject,
		Issuer:   claims.Issuer,
		ClientID: claims.ClientID,
		Scopes:   scopes,
		KeyID:    keyID,
	}
	if len(claims.Audience) > 0 {
		verified.Audience = claims.Audience[0]
	}
	if claims.ExpiresAt != nil {
		verified.ExpiresAt = claims.ExpiresAt.Time
	}
	if claims.IssuedAt != nil {
		verified.IssuedAt = claims.IssuedAt.Time
	}

	return verified, nil
}

func (s *Service) parseAccessToken(rawToken string) (*accessTokenClaims, string, error) {
	keys := s.snapshotJWKS()
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.audience),
		jwt.WithTimeFunc(s.now),
	)

	claims := &accessTokenClaims{}
	var keyID string
	parsed, err := parser.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
		selectedKeyID, publicKey, selectErr := selectVerificationKey(keys, token)
		if selectErr != nil {
			return nil, selectErr
		}

		keyID = selectedKeyID
		return publicKey, nil
	})
	if err != nil {
		return nil, "", err
	}
	if !parsed.Valid {
		return nil, "", errors.New("access token is invalid")
	}

	return claims, keyID, nil
}

func (s *Service) snapshotJWKS() map[string]*rsa.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot := make(map[string]*rsa.PublicKey, len(s.jwks))
	for keyID, key := range s.jwks {
		snapshot[keyID] = key
	}

	return snapshot
}

func (s *Service) ensureDiscovery(ctx context.Context, force bool) (oidc.DiscoveryMetadata, error) {
	s.mu.RLock()
	if !force && s.discovery.Issuer != "" && !cacheExpired(s.discoveryFetched, s.cacheTTL, s.now) {
		discovery := s.discovery
		s.mu.RUnlock()
		return discovery, nil
	}
	s.mu.RUnlock()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return oidc.DiscoveryMetadata{}, fmt.Errorf("build discovery request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return oidc.DiscoveryMetadata{}, fmt.Errorf("fetch discovery metadata: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return oidc.DiscoveryMetadata{}, fmt.Errorf("fetch discovery metadata: unexpected status %d", response.StatusCode)
	}

	var metadata oidc.DiscoveryMetadata
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		return oidc.DiscoveryMetadata{}, fmt.Errorf("decode discovery metadata: %w", err)
	}

	s.mu.Lock()
	s.discovery = metadata
	s.discoveryFetched = s.now()
	s.mu.Unlock()

	return metadata, nil
}

func (s *Service) ensureJWKS(ctx context.Context, force bool) error {
	s.mu.RLock()
	if !force && len(s.jwks) > 0 && !cacheExpired(s.jwksFetched, s.cacheTTL, s.now) {
		s.mu.RUnlock()
		return nil
	}
	s.mu.RUnlock()

	discovery, err := s.ensureDiscovery(ctx, force)
	if err != nil {
		return err
	}
	if strings.TrimSpace(discovery.JWKSURI) == "" {
		return errors.New("jwks_uri is empty")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}

	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: unexpected status %d", response.StatusCode)
	}

	var jwks oidc.JWKS
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if strings.TrimSpace(key.Kid) == "" {
			continue
		}
		publicKey, err := oidc.DecodeRSAPublicKeyJWK(key)
		if err != nil {
			return fmt.Errorf("decode jwk %q: %w", key.Kid, err)
		}
		keys[key.Kid] = publicKey
	}

	s.mu.Lock()
	s.jwks = keys
	s.jwksFetched = s.now()
	s.mu.Unlock()

	return nil
}

func selectVerificationKey(keys map[string]*rsa.PublicKey, token *jwt.Token) (string, *rsa.PublicKey, error) {
	keyID, _ := token.Header["kid"].(string)
	if keyID != "" {
		publicKey, ok := keys[keyID]
		if !ok || publicKey == nil {
			return "", nil, errUnknownKeyID
		}
		return keyID, publicKey, nil
	}
	if len(keys) != 1 {
		return "", nil, errUnknownKeyID
	}

	for resolvedKeyID, publicKey := range keys {
		return resolvedKeyID, publicKey, nil
	}

	return "", nil, errUnknownKeyID
}

func cacheExpired(fetchedAt time.Time, ttl time.Duration, now func() time.Time) bool {
	if fetchedAt.IsZero() {
		return true
	}

	return now().After(fetchedAt.Add(ttl))
}
