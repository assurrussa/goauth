//nolint:tagliatelle // Verifier validates JWT access tokens and uses protocol snake_case claims.
package verifier

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/assurrussa/goauth/oidc"
)

const (
	defaultHTTPTimeout              = 5 * time.Second
	defaultCacheTTL                 = 5 * time.Minute
	defaultMaxResponseBytes   int64 = 1 << 20
	unknownKeyRefreshCooldown       = 30 * time.Second
	failedRefreshCooldown           = time.Second
	tokenUseAccess                  = "access"
)

var errUnknownKeyID = errors.New("oidc verifier key id was not found in jwks")

// AccessTokenProfile defines the issuer-specific evidence that a JWT is an access token.
// Profiles are explicit: signature, issuer and audience alone do not distinguish ID tokens.
type AccessTokenProfile string

const (
	AccessTokenProfileGoAuth  AccessTokenProfile = "goauth"
	AccessTokenProfileZITADEL AccessTokenProfile = "zitadel-jwt" //nolint:gosec // Public profile name, not a credential.
)

type Options struct {
	// AccessTokenProfile defaults to GoAuth, which requires token_use=access.
	AccessTokenProfile AccessTokenProfile
	Issuer             string
	// DiscoveryURL overrides the discovery endpoint without changing issuer identity.
	DiscoveryURL string
	// HTTPTimeout bounds each fetch, including clients without a Timeout. Defaults to five seconds.
	HTTPTimeout time.Duration
	// MaxResponseBytes bounds each discovery or JWKS response. Defaults to one MiB.
	MaxResponseBytes int64
	// AllowInsecureHTTP explicitly permits HTTP endpoints for local development.
	AllowInsecureHTTP bool
	Audience          string
	RequiredScopes    []string
	HTTPClient        *http.Client
	CacheTTL          time.Duration
	Now               func() time.Time
}

type Service struct {
	accessTokenProfile AccessTokenProfile
	issuer             string
	discoveryURL       string
	httpTimeout        time.Duration
	maxResponseBytes   int64
	allowInsecureHTTP  bool
	audience           string
	requiredScopes     []string
	httpClient         *http.Client
	cacheTTL           time.Duration
	now                func() time.Time

	mu               sync.RWMutex
	discovery        oidc.DiscoveryMetadata
	discoveryFetched time.Time
	jwks             map[string]*rsa.PublicKey
	jwksFetched      time.Time
	refresh          *refreshFlight
	unknownRefreshAt time.Time
	refreshRetryAt   time.Time
	refreshFailure   error
}

type refreshFlight struct {
	done chan struct{}
	err  error
}

type accessTokenClaims struct {
	raw      map[string]json.RawMessage
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

func (c *accessTokenClaims) UnmarshalJSON(data []byte) error {
	type plain accessTokenClaims
	if err := json.Unmarshal(data, (*plain)(c)); err != nil {
		return err
	}
	return json.Unmarshal(data, &c.raw)
}

func New(opts Options) (*Service, error) {
	profile := opts.AccessTokenProfile
	if profile == "" {
		profile = AccessTokenProfileGoAuth
	}
	if profile != AccessTokenProfileGoAuth && profile != AccessTokenProfileZITADEL {
		return nil, errors.New("unsupported access token profile")
	}
	issuer := opts.Issuer
	if issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if strings.Contains(issuer, "?") {
		return nil, errors.New("issuer must not contain a query")
	}
	if err := validateEndpoint(issuer, opts.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}
	discoveryURL := opts.DiscoveryURL
	if discoveryURL == "" {
		discoveryURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	}
	if err := validateEndpoint(discoveryURL, opts.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("invalid discovery URL: %w", err)
	}
	audience := strings.TrimSpace(opts.Audience)
	if audience == "" {
		return nil, errors.New("audience is required")
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	clientCopy := *httpClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	httpTimeout := opts.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = defaultHTTPTimeout
	}
	maxResponseBytes := opts.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = defaultMaxResponseBytes
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
		accessTokenProfile: profile,
		issuer:             issuer,
		discoveryURL:       discoveryURL,
		httpTimeout:        httpTimeout,
		maxResponseBytes:   maxResponseBytes,
		allowInsecureHTTP:  opts.AllowInsecureHTTP,
		audience:           audience,
		requiredScopes:     oidc.NormalizeScopes(opts.RequiredScopes),
		httpClient:         &clientCopy,
		cacheTTL:           cacheTTL,
		now:                now,
		jwks:               make(map[string]*rsa.PublicKey),
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
	if err := s.validateTokenProfile(claims); err != nil {
		return VerifiedAccessToken{}, err
	}

	scopes := oidc.ParseScope(claims.Scope)
	for _, requiredScope := range s.requiredScopes {
		if !oidc.HasScope(scopes, requiredScope) {
			return VerifiedAccessToken{}, fmt.Errorf("required scope %q is missing", requiredScope)
		}
	}

	// Audience is the audience actually checked, not the first entry in aud.
	verified := VerifiedAccessToken{
		Subject:  claims.Subject,
		Issuer:   claims.Issuer,
		Audience: s.audience,
		ClientID: claims.ClientID,
		Scopes:   scopes,
		KeyID:    keyID,
	}
	if claims.ExpiresAt != nil {
		verified.ExpiresAt = claims.ExpiresAt.Time
	}
	if claims.IssuedAt != nil {
		verified.IssuedAt = claims.IssuedAt.Time
	}

	return verified, nil
}

func (s *Service) validateTokenProfile(claims *accessTokenClaims) error {
	use, present := claims.raw["token_use"]
	var tokenUse string
	if present {
		if err := json.Unmarshal(use, &tokenUse); err != nil || tokenUse != tokenUseAccess {
			return errors.New("token_use must be access")
		}
	}
	if s.accessTokenProfile == AccessTokenProfileGoAuth {
		if !present {
			return errors.New("token_use must be access")
		}
		return nil
	}
	// ZITADEL v4 access tokens have jti and nbf; ID and logout JWTs have
	// authentication/session claims instead. Presence, including null or empty
	// values, is rejected so malformed claims cannot erase the token distinction.
	for _, name := range []string{"nonce", "auth_time", "amr", "acr", "sid", "events", "at_hash", "c_hash", "s_hash"} {
		if _, present := claims.raw[name]; present {
			return fmt.Errorf("claim %q is not allowed in a ZITADEL access token", name)
		}
	}
	var tokenID string
	if err := json.Unmarshal(claims.raw["jti"], &tokenID); err != nil || strings.TrimSpace(tokenID) == "" {
		return errors.New("jti is required for a ZITADEL access token")
	}
	nbf := strings.TrimSpace(string(claims.raw["nbf"]))
	if claims.NotBefore == nil || nbf == "" || nbf[0] == '"' || nbf == "null" {
		return errors.New("numeric nbf is required for a ZITADEL access token")
	}
	var declaredNBF jwt.NumericDate
	if err := json.Unmarshal(claims.raw["nbf"], &declaredNBF); err != nil || !declaredNBF.Equal(claims.NotBefore.Time) {
		return errors.New("nbf claim is ambiguous or malformed")
	}
	if !claims.NotBefore.Before(claims.ExpiresAt.Time) {
		return errors.New("nbf must precede exp")
	}
	return nil
}

func (s *Service) parseAccessToken(rawToken string) (*accessTokenClaims, string, error) {
	keys := s.snapshotJWKS()
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(s.audience),
		jwt.WithTimeFunc(s.now),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
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

	if claims.Subject == "" {
		return nil, "", errors.New("subject is required")
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

// Fetches are serialized by ensureJWKS, so discovery and key rotation share one flight.
func (s *Service) ensureDiscovery(ctx context.Context) (oidc.DiscoveryMetadata, error) {
	s.mu.RLock()
	if s.discovery.Issuer != "" && !cacheExpired(s.discoveryFetched, s.cacheTTL, s.now) {
		discovery := s.discovery
		s.mu.RUnlock()
		return discovery, nil
	}
	s.mu.RUnlock()
	var metadata oidc.DiscoveryMetadata
	if err := s.fetchJSON(ctx, s.discoveryURL, &metadata); err != nil {
		return oidc.DiscoveryMetadata{}, fmt.Errorf("fetch discovery metadata: %w", err)
	}
	if metadata.Issuer != s.issuer {
		return oidc.DiscoveryMetadata{}, errors.New("discovery issuer does not match configured issuer")
	}
	if err := validateEndpoint(metadata.JWKSURI, s.allowInsecureHTTP); err != nil {
		return oidc.DiscoveryMetadata{}, fmt.Errorf("invalid jwks_uri: %w", err)
	}
	s.mu.Lock()
	s.discovery = metadata
	s.discoveryFetched = s.now()
	s.mu.Unlock()
	return metadata, nil
}

func (s *Service) ensureJWKS(ctx context.Context, force bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if !force && len(s.jwks) > 0 && !cacheExpired(s.jwksFetched, s.cacheTTL, s.now) {
		s.mu.Unlock()
		return nil
	}
	if flight := s.refresh; flight != nil {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-flight.done:
			return flight.err
		}
	}
	// A fast upstream failure must not turn sequential requests into a fetch
	// storm. An expired cache remains fail-closed; valid cached keys above are
	// not disabled by an unrelated failed unknown-kid refresh.
	if s.refreshFailure != nil && s.now().Before(s.refreshRetryAt) {
		err := s.refreshFailure
		s.mu.Unlock()
		return err
	}
	if force && !s.unknownRefreshAt.IsZero() && s.now().Before(s.unknownRefreshAt.Add(unknownKeyRefreshCooldown)) {
		s.mu.Unlock()
		return nil
	}
	flight := &refreshFlight{done: make(chan struct{})}
	s.refresh = flight
	if force {
		s.unknownRefreshAt = s.now()
	}
	s.mu.Unlock()
	// A caller can stop waiting without canceling the refresh shared by other callers.
	// Bound the whole flight as well as the individual HTTP fetches.
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.httpTimeout)
	go func() {
		defer cancel()
		err := s.refreshJWKS(refreshCtx)
		s.mu.Lock()
		flight.err = err
		s.refreshFailure = err
		if err != nil {
			s.refreshRetryAt = s.now().Add(failedRefreshCooldown)
		} else {
			s.refreshRetryAt = time.Time{}
		}
		s.refresh = nil
		close(flight.done)
		s.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-flight.done:
		return flight.err
	}
}

func (s *Service) refreshJWKS(ctx context.Context) error {
	discovery, err := s.ensureDiscovery(ctx)
	if err != nil {
		return err
	}
	var jwks oidc.JWKS
	if err := s.fetchJSON(ctx, discovery.JWKSURI, &jwks); err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	keys, err := verificationKeys(jwks)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.jwks = keys
	s.jwksFetched = s.now()
	s.mu.Unlock()
	return nil
}

func (s *Service) fetchJSON(ctx context.Context, endpoint string, target any) error {
	if err := validateEndpoint(endpoint, s.allowInsecureHTTP); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.httpTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, s.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > s.maxResponseBytes {
		return errors.New("response exceeds maximum size")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func validateEndpoint(endpoint string, allowInsecureHTTP bool) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("endpoint must be an absolute URL without credentials or fragment")
	}
	if parsed.Scheme != "https" && (!allowInsecureHTTP || parsed.Scheme != "http") {
		return errors.New("endpoint must use HTTPS")
	}
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
