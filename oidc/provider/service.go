//nolint:tagliatelle // OIDC provider uses direct JWT claims and RFC-defined snake_case names.
package provider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/generate_token"
	"github.com/assurrussa/goauth/oidc"
)

const (
	grantTypeAuthorizationCode = "authorization_code"
	grantTypeRefreshToken      = "refresh_token"
	responseTypeCode           = "code"
	codeChallengeMethodS256    = "S256"
	tokenUseAccess             = "access"
	tokenUseID                 = "id"
	maxAccessTokenTTL          = 5 * time.Minute
)

type Options struct {
	Clients                  oidc.ClientStore
	Requests                 oidc.AuthorizationRequestStore
	Codes                    oidc.AuthorizationCodeStore
	RefreshTokens            oidc.RefreshTokenStore
	Keys                     oidc.TokenSigningKeyStore
	Claims                   oidc.ClaimsResolver
	Issuer                   string
	FrontendLoginURL         string
	TokenEndpointAuthMethods []string
	RequestTTL               time.Duration
	CodeTTL                  time.Duration
	AccessTokenTTL           time.Duration
	RefreshTokenTTL          time.Duration
	Now                      func() time.Time
	GenerateToken            func() (string, error)
}

type Service struct {
	enabled                  bool
	clients                  oidc.ClientStore
	requests                 oidc.AuthorizationRequestStore
	codes                    oidc.AuthorizationCodeStore
	refreshTokens            oidc.RefreshTokenStore
	keys                     oidc.TokenSigningKeyStore
	claims                   oidc.ClaimsResolver
	issuer                   string
	frontendLoginURL         string
	tokenEndpointAuthMethods []string
	requestTTL               time.Duration
	codeTTL                  time.Duration
	accessTokenTTL           time.Duration
	refreshTokenTTL          time.Duration
	now                      func() time.Time
	generateToken            func() (string, error)
}

type accessTokenClaims struct {
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	TokenUse string `json:"token_use"`
	jwt.RegisteredClaims
}

type idTokenClaims struct {
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
	TokenUse          string `json:"token_use,omitempty"`
	AuthTime          int64  `json:"auth_time"`
	jwt.RegisteredClaims
}

type authorizationCodeInput struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
}

func NewDisabled() *Service {
	return &Service{}
}

func Must(opts Options) *Service {
	svc, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("panic: %w", err))
	}

	return svc
}

func New(opts Options) (*Service, error) {
	switch {
	case opts.Clients == nil:
		return nil, errors.New("clients are required")
	case opts.Requests == nil:
		return nil, errors.New("authorization requests are required")
	case opts.Codes == nil:
		return nil, errors.New("authorization codes are required")
	case opts.RefreshTokens == nil:
		return nil, errors.New("refresh tokens are required")
	case opts.Keys == nil:
		return nil, errors.New("keys are required")
	case opts.Claims == nil:
		return nil, errors.New("claims resolver is required")
	case strings.TrimSpace(opts.Issuer) == "":
		return nil, errors.New("issuer is required")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	generateToken := opts.GenerateToken
	if generateToken == nil {
		generateToken = generate_token.GenerateToken
	}

	requestTTL := opts.RequestTTL
	if requestTTL <= 0 {
		requestTTL = 10 * time.Minute
	}
	codeTTL := opts.CodeTTL
	if codeTTL <= 0 {
		codeTTL = 5 * time.Minute
	}
	accessTTL := opts.AccessTokenTTL
	if accessTTL <= 0 {
		accessTTL = maxAccessTokenTTL
	}
	if accessTTL > maxAccessTokenTTL {
		return nil, fmt.Errorf("OIDC access token TTL must not exceed %s", maxAccessTokenTTL)
	}
	refreshTTL := opts.RefreshTokenTTL
	if refreshTTL <= 0 {
		refreshTTL = 30 * 24 * time.Hour
	}
	tokenEndpointAuthMethods := oidc.SupportedTokenEndpointAuthMethods(opts.TokenEndpointAuthMethods)

	return &Service{
		enabled:                  true,
		clients:                  opts.Clients,
		requests:                 opts.Requests,
		codes:                    opts.Codes,
		refreshTokens:            opts.RefreshTokens,
		keys:                     opts.Keys,
		claims:                   opts.Claims,
		issuer:                   strings.TrimRight(strings.TrimSpace(opts.Issuer), "/"),
		frontendLoginURL:         strings.TrimSpace(opts.FrontendLoginURL),
		tokenEndpointAuthMethods: tokenEndpointAuthMethods,
		requestTTL:               requestTTL,
		codeTTL:                  codeTTL,
		accessTokenTTL:           accessTTL,
		refreshTokenTTL:          refreshTTL,
		now:                      now,
		generateToken:            generateToken,
	}, nil
}

func (s *Service) Enabled() bool {
	return s != nil && s.enabled
}

func (s *Service) Discovery(_ context.Context) oidc.DiscoveryMetadata {
	return oidc.DiscoveryMetadata{
		Issuer:                            s.issuer,
		AuthorizationEndpoint:             s.issuer + "/oauth2/authorize",
		TokenEndpoint:                     s.issuer + "/oauth2/token",
		UserInfoEndpoint:                  s.issuer + "/oauth2/userinfo",
		JWKSURI:                           s.issuer + "/oauth2/jwks",
		RevocationEndpoint:                s.issuer + "/oauth2/revoke",
		ResponseTypesSupported:            []string{responseTypeCode},
		GrantTypesSupported:               []string{grantTypeAuthorizationCode, grantTypeRefreshToken},
		ScopesSupported:                   oidc.SupportedScopes(),
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: append([]string(nil), s.tokenEndpointAuthMethods...),
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "preferred_username",
		},
		CodeChallengeMethodsSupported: []string{codeChallengeMethodS256},
	}
}

func (s *Service) JWKS(ctx context.Context) (oidc.JWKS, error) {
	if !s.Enabled() {
		return oidc.JWKS{}, nil
	}

	keys, err := s.keys.Public(ctx)
	if err != nil {
		return oidc.JWKS{}, fmt.Errorf("get jwks: %w", err)
	}

	return oidc.JWKS{Keys: keys}, nil
}

func (s *Service) Authorize(
	ctx context.Context,
	req oidc.AuthorizeRequest,
	current *oidc.AuthenticatedSubject,
) (*oidc.AuthorizeResult, error) {
	client, err := s.clients.Get(ctx, strings.TrimSpace(req.ClientID))
	if err != nil || client.ID == "" {
		return nil, s.oauthError("invalid_client", "unknown client", http.StatusBadRequest)
	}
	if !s.redirectAllowed(client, req.RedirectURI) {
		return nil, s.oauthError("invalid_request", "invalid redirect_uri", http.StatusBadRequest)
	}

	scopes, oauthErr := s.validateAuthorizeRequest(client, req)
	if oauthErr != nil {
		return &oidc.AuthorizeResult{
			RedirectURI: s.redirectWithError(req.RedirectURI, req.State, oauthErr),
		}, nil
	}

	if current == nil || current.Account.IsZero() {
		challenge, err := s.generateToken()
		if err != nil {
			return nil, fmt.Errorf("generate challenge: %w", err)
		}

		now := s.now()
		if err := s.requests.Save(ctx, oidc.AuthorizationRequest{
			Challenge:           challenge,
			ClientID:            client.ID,
			RedirectURI:         req.RedirectURI,
			State:               req.State,
			Nonce:               req.Nonce,
			Scopes:              scopes,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			RequestedAt:         now,
			ExpiresAt:           now.Add(s.requestTTL),
		}); err != nil {
			return nil, fmt.Errorf("save authorization request: %w", err)
		}

		return &oidc.AuthorizeResult{RedirectURI: s.loginRedirect(challenge)}, nil
	}

	return s.issueAuthorizationCode(ctx, authorizationCodeInput{
		ClientID:            client.ID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		Nonce:               req.Nonce,
		Scopes:              scopes,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}, *current)
}

func (s *Service) ContinueAuthorization(
	ctx context.Context,
	challenge string,
	current *oidc.AuthenticatedSubject,
) (*oidc.AuthorizeResult, error) {
	challenge = strings.TrimSpace(challenge)
	if current == nil || current.Account.IsZero() {
		record, err := s.requests.Get(ctx, challenge)
		if err != nil {
			if errors.Is(err, oidc.ErrAuthorizationRequestNotFound) {
				return nil, s.oauthError("invalid_request", "authorization challenge not found", http.StatusBadRequest)
			}

			return nil, fmt.Errorf("get authorization request: %w", err)
		}
		if s.now().After(record.ExpiresAt) {
			_, _ = s.requests.Consume(ctx, record.Challenge)
			return nil, s.oauthError("invalid_request", "authorization challenge expired", http.StatusBadRequest)
		}

		return &oidc.AuthorizeResult{RedirectURI: s.loginRedirect(record.Challenge)}, nil
	}

	record, err := s.requests.Consume(ctx, challenge)
	if err != nil {
		if errors.Is(err, oidc.ErrAuthorizationRequestNotFound) {
			return nil, s.oauthError("invalid_request", "authorization challenge not found", http.StatusBadRequest)
		}

		return nil, fmt.Errorf("consume authorization request: %w", err)
	}
	if s.now().After(record.ExpiresAt) {
		return nil, s.oauthError("invalid_request", "authorization challenge expired", http.StatusBadRequest)
	}

	result, err := s.issueAuthorizationCode(
		ctx,
		authorizationCodeInput{
			ClientID:            record.ClientID,
			RedirectURI:         record.RedirectURI,
			State:               record.State,
			Nonce:               record.Nonce,
			Scopes:              record.Scopes,
			CodeChallenge:       record.CodeChallenge,
			CodeChallengeMethod: record.CodeChallengeMethod,
		},
		*current,
	)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (s *Service) ExchangeToken(ctx context.Context, req oidc.TokenRequest) (*oidc.TokenResponse, error) {
	switch strings.TrimSpace(req.GrantType) {
	case grantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, req)
	case grantTypeRefreshToken:
		return s.refreshToken(ctx, req)
	default:
		return nil, s.oauthError("unsupported_grant_type", "grant_type is not supported", http.StatusBadRequest)
	}
}

func (s *Service) Revoke(ctx context.Context, req oidc.RevokeRequest) error {
	if strings.TrimSpace(req.Token) == "" {
		return s.oauthError("invalid_request", "token is required", http.StatusBadRequest)
	}

	client, err := s.authenticateClient(ctx, req.ClientID, req.ClientSecret, req.ClientAuthMethod)
	if err != nil {
		return err
	}

	record, err := s.refreshTokens.Get(ctx, req.Token)
	if err != nil {
		if errors.Is(err, oidc.ErrRefreshTokenNotFound) {
			return nil
		}

		return fmt.Errorf("get refresh token: %w", err)
	}
	if record.Token == "" || record.ClientID != client.ID {
		return nil
	}

	return s.refreshTokens.Revoke(ctx, req.Token, s.now())
}

func (s *Service) UserInfo(ctx context.Context, accessToken string) (oidc.UserInfo, error) {
	claims, err := s.parseAccessToken(ctx, accessToken)
	if err != nil {
		return oidc.UserInfo{}, s.oauthError("invalid_token", "invalid access token", http.StatusUnauthorized)
	}
	if claims.TokenUse != tokenUseAccess {
		return oidc.UserInfo{}, s.oauthError("invalid_token", "invalid access token", http.StatusUnauthorized)
	}

	subject, err := s.claims.Resolve(ctx, claims.Subject)
	if err != nil {
		return oidc.UserInfo{}, fmt.Errorf("resolve subject: %w", err)
	}
	if subject.IsZero() || subject.Subject.Status != goauth.SubjectStatusActive {
		return oidc.UserInfo{}, s.oauthError("invalid_token", "subject not found", http.StatusUnauthorized)
	}

	scopes := oidc.ParseScope(claims.Scope)
	return s.buildUserInfo(subject, scopes), nil
}

func (s *Service) issueAuthorizationCode(
	ctx context.Context,
	input authorizationCodeInput,
	current oidc.AuthenticatedSubject,
) (*oidc.AuthorizeResult, error) {
	code, err := s.generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate authorization code: %w", err)
	}

	now := s.now()
	if err := s.codes.Save(ctx, oidc.AuthorizationCode{
		Code:                code,
		SubjectID:           current.Account.Subject.ID.String(),
		ClientID:            input.ClientID,
		RedirectURI:         input.RedirectURI,
		Scopes:              oidc.NormalizeScopes(input.Scopes),
		Nonce:               strings.TrimSpace(input.Nonce),
		CodeChallenge:       strings.TrimSpace(input.CodeChallenge),
		CodeChallengeMethod: strings.TrimSpace(input.CodeChallengeMethod),
		AuthenticatedAt:     current.AuthenticatedAt,
		CreatedAt:           now,
		ExpiresAt:           now.Add(s.codeTTL),
	}); err != nil {
		return nil, fmt.Errorf("save authorization code: %w", err)
	}

	redirectTarget, err := url.Parse(input.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("parse redirect uri: %w", err)
	}
	query := redirectTarget.Query()
	query.Set("code", code)
	if strings.TrimSpace(input.State) != "" {
		query.Set("state", input.State)
	}
	redirectTarget.RawQuery = query.Encode()

	return &oidc.AuthorizeResult{RedirectURI: redirectTarget.String()}, nil
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, req oidc.TokenRequest) (*oidc.TokenResponse, error) {
	client, err := s.authenticateClient(ctx, req.ClientID, req.ClientSecret, req.ClientAuthMethod)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Code) == "" {
		return nil, s.oauthError("invalid_grant", "code is required", http.StatusBadRequest)
	}

	code, err := s.codes.Consume(ctx, req.Code)
	if err != nil {
		if errors.Is(err, oidc.ErrAuthorizationCodeNotFound) {
			return nil, s.oauthError("invalid_grant", "authorization code not found", http.StatusBadRequest)
		}

		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	if s.now().After(code.ExpiresAt) {
		return nil, s.oauthError("invalid_grant", "authorization code expired", http.StatusBadRequest)
	}
	if code.ClientID != client.ID || code.RedirectURI != strings.TrimSpace(req.RedirectURI) {
		return nil, s.oauthError("invalid_grant", "authorization code is not valid for this client", http.StatusBadRequest)
	}
	if !verifyCodeVerifier(req.CodeVerifier, code.CodeChallenge) {
		return nil, s.oauthError("invalid_grant", "pkce verification failed", http.StatusBadRequest)
	}

	subject, err := s.claims.Resolve(ctx, code.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("resolve subject: %w", err)
	}
	if subject.IsZero() || subject.Subject.Status != goauth.SubjectStatusActive {
		return nil, s.oauthError("invalid_grant", "subject not found", http.StatusBadRequest)
	}

	response, err := s.issueTokens(ctx, subject, client, code.Scopes, code.AuthenticatedAt, code.Nonce, "")
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Service) refreshToken(ctx context.Context, req oidc.TokenRequest) (*oidc.TokenResponse, error) {
	client, err := s.authenticateClient(ctx, req.ClientID, req.ClientSecret, req.ClientAuthMethod)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		return nil, s.oauthError("invalid_grant", "refresh token is required", http.StatusBadRequest)
	}

	record, err := s.refreshTokens.Get(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, oidc.ErrRefreshTokenNotFound) {
			return nil, s.oauthError("invalid_grant", "refresh token not found", http.StatusBadRequest)
		}

		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if record.ClientID != client.ID {
		return nil, s.oauthError("invalid_grant", "refresh token does not belong to the client", http.StatusBadRequest)
	}
	if record.RevokedAt != nil || s.now().After(record.ExpiresAt) {
		_ = s.refreshTokens.Revoke(ctx, record.Token, s.now())
		return nil, s.oauthError("invalid_grant", "refresh token is not active", http.StatusBadRequest)
	}

	subject, err := s.claims.Resolve(ctx, record.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("resolve subject: %w", err)
	}
	if subject.IsZero() || subject.Subject.Status != goauth.SubjectStatusActive ||
		subject.Subject.SecurityVersion != record.SecurityVersion {
		_ = s.refreshTokens.Revoke(ctx, record.Token, s.now())
		return nil, s.oauthError("invalid_grant", "refresh token is no longer valid", http.StatusBadRequest)
	}

	nextRefreshToken := ""
	if oidc.HasScope(record.Scopes, oidc.ScopeOfflineAccess) {
		nextRefreshToken, err = s.generateToken()
		if err != nil {
			return nil, fmt.Errorf("generate refresh token: %w", err)
		}
	}

	response, nextRecord, err := s.issueTokensWithRefresh(
		ctx,
		subject,
		client,
		record.Scopes,
		record.AuthenticatedAt,
		"",
		nextRefreshToken,
	)
	if err != nil {
		return nil, err
	}
	if nextRecord.Token != "" {
		if err := s.refreshTokens.Rotate(ctx, record.Token, nextRecord, s.now()); err != nil {
			if errors.Is(err, oidc.ErrRefreshTokenNotFound) || errors.Is(err, oidc.ErrRefreshTokenReplay) {
				return nil, s.oauthError("invalid_grant", "refresh token was already rotated", http.StatusBadRequest)
			}
			return nil, fmt.Errorf("rotate refresh token: %w", err)
		}
	}

	return response, nil
}

func (s *Service) issueTokens(
	ctx context.Context,
	account goauth.Account,
	client oidc.Client,
	scopes []string,
	authenticatedAt time.Time,
	nonce, refreshToken string,
) (*oidc.TokenResponse, error) {
	response, nextRecord, err := s.issueTokensWithRefresh(ctx, account, client, scopes, authenticatedAt, nonce, refreshToken)
	if err != nil {
		return nil, err
	}
	if nextRecord.Token != "" {
		if err := s.refreshTokens.Save(ctx, nextRecord); err != nil {
			return nil, fmt.Errorf("save refresh token: %w", err)
		}
	}

	return response, nil
}

func (s *Service) issueTokensWithRefresh(
	ctx context.Context,
	account goauth.Account,
	client oidc.Client,
	scopes []string,
	authenticatedAt time.Time,
	nonce, refreshToken string,
) (*oidc.TokenResponse, oidc.RefreshToken, error) {
	accessToken, err := s.signAccessToken(ctx, account, client.ID, scopes)
	if err != nil {
		return nil, oidc.RefreshToken{}, fmt.Errorf("sign access token: %w", err)
	}
	idToken, err := s.signIDToken(ctx, account, client.ID, scopes, authenticatedAt, nonce)
	if err != nil {
		return nil, oidc.RefreshToken{}, fmt.Errorf("sign id token: %w", err)
	}

	response := &oidc.TokenResponse{
		AccessToken: accessToken,
		IDToken:     idToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       oidc.ScopeString(scopes),
	}

	var record oidc.RefreshToken
	if oidc.HasScope(scopes, oidc.ScopeOfflineAccess) {
		if strings.TrimSpace(refreshToken) == "" {
			refreshToken, err = s.generateToken()
			if err != nil {
				return nil, oidc.RefreshToken{}, fmt.Errorf("generate refresh token: %w", err)
			}
		}

		now := s.now()
		record = oidc.RefreshToken{
			Token:           refreshToken,
			SubjectID:       account.Subject.ID.String(),
			ClientID:        client.ID,
			Scopes:          oidc.NormalizeScopes(scopes),
			SecurityVersion: account.Subject.SecurityVersion,
			AuthenticatedAt: authenticatedAt,
			CreatedAt:       now,
			ExpiresAt:       now.Add(s.refreshTokenTTL),
		}
		response.RefreshToken = refreshToken
	}

	return response, record, nil
}

func (s *Service) buildUserInfo(account goauth.Account, scopes []string) oidc.UserInfo {
	info := oidc.UserInfo{Subject: account.Subject.ID.String()}
	if oidc.HasScope(scopes, oidc.ScopeEmail) && account.PrimaryEmail.DisplayValue != "" {
		info.Email = account.PrimaryEmail.DisplayValue
		verified := account.EmailVerified()
		info.EmailVerified = &verified
	}
	if oidc.HasScope(scopes, oidc.ScopeProfile) {
		info.Name = account.Profile.DisplayName
		info.PreferredUsername = account.Profile.Username
	}

	return info
}

func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret, authMethod string) (oidc.Client, error) {
	clientID = strings.TrimSpace(clientID)
	client, err := s.clients.Get(ctx, clientID)
	if err != nil || client.ID == "" {
		return oidc.Client{}, s.oauthError("invalid_client", "unknown client", http.StatusUnauthorized)
	}

	expectedAuthMethod := oidc.ClientTokenEndpointAuthMethod(client)
	actualAuthMethod := oidc.NormalizeTokenEndpointAuthMethod(authMethod, "")
	if expectedAuthMethod != actualAuthMethod {
		return oidc.Client{}, s.oauthError("invalid_client", "invalid client authentication method", http.StatusUnauthorized)
	}

	if expectedAuthMethod == oidc.TokenEndpointAuthMethodNone {
		return client, nil
	}
	if subtleStringCompare(client.Secret, strings.TrimSpace(clientSecret)) {
		return client, nil
	}

	return oidc.Client{}, s.oauthError("invalid_client", "invalid client credentials", http.StatusUnauthorized)
}

func (s *Service) validateAuthorizeRequest(client oidc.Client, req oidc.AuthorizeRequest) ([]string, *oidc.OAuthError) {
	if !client.Trusted {
		return nil, s.oauthError("unauthorized_client", "client is not trusted", http.StatusBadRequest)
	}
	if strings.TrimSpace(req.ResponseType) != responseTypeCode {
		return nil, s.oauthError("unsupported_response_type", "response_type must be code", http.StatusBadRequest)
	}

	scopes := oidc.ParseScope(req.Scope)
	if len(scopes) == 0 || !oidc.HasScope(scopes, oidc.ScopeOpenID) {
		return nil, s.oauthError("invalid_scope", "openid scope is required", http.StatusBadRequest)
	}
	for _, scope := range scopes {
		if !oidc.IsSupportedScope(scope) {
			return nil, s.oauthError("invalid_scope", "unsupported scope", http.StatusBadRequest)
		}
		if !oidc.HasScope(client.AllowedScopes, scope) {
			return nil, s.oauthError("invalid_scope", "scope is not allowed for this client", http.StatusBadRequest)
		}
	}

	if client.RequirePKCE && strings.TrimSpace(req.CodeChallenge) == "" {
		return nil, s.oauthError("invalid_request", "code_challenge is required", http.StatusBadRequest)
	}
	if client.RequirePKCE && strings.TrimSpace(req.CodeChallengeMethod) != codeChallengeMethodS256 {
		return nil, s.oauthError("invalid_request", "code_challenge_method must be S256", http.StatusBadRequest)
	}

	return scopes, nil
}

func (s *Service) redirectAllowed(client oidc.Client, redirectURI string) bool {
	redirectURI = strings.TrimSpace(redirectURI)
	for _, candidate := range client.RedirectURIs {
		if strings.TrimSpace(candidate) == redirectURI {
			return true
		}
	}

	return false
}

func (s *Service) redirectWithError(redirectURI, state string, oauthErr *oidc.OAuthError) string {
	target, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	query := target.Query()
	query.Set("error", oauthErr.Code)
	if oauthErr.Description != "" {
		query.Set("error_description", oauthErr.Description)
	}
	if strings.TrimSpace(state) != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()

	return target.String()
}

func (s *Service) loginRedirect(challenge string) string {
	base := strings.TrimSpace(s.frontendLoginURL)
	if base == "" {
		base = "/login"
	}
	target, err := url.Parse(base)
	if err != nil {
		return base
	}
	query := target.Query()
	query.Set("oidc_challenge", challenge)
	target.RawQuery = query.Encode()

	return target.String()
}

func (s *Service) oauthError(code, description string, statusCode int) *oidc.OAuthError {
	return &oidc.OAuthError{
		Code:        code,
		Description: description,
		StatusCode:  statusCode,
	}
}

func verifyCodeVerifier(verifier, challenge string) bool {
	verifier = strings.TrimSpace(verifier)
	challenge = strings.TrimSpace(challenge)
	if verifier == "" || challenge == "" {
		return false
	}

	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtleStringCompare(expected, challenge)
}

func subtleStringCompare(left, right string) bool {
	if len(left) != len(right) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
