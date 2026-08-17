//nolint:tagliatelle // OIDC DTOs intentionally use protocol token fields and snake_case JSON names.
package oidc

import (
	"crypto/rsa"
	"slices"
	"strings"
	"time"

	"github.com/assurrussa/goauth"
)

const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
	ScopeAPIRead       = "api:read"
	ScopeAPIWrite      = "api:write"

	TokenEndpointAuthMethodNone              = "none"
	TokenEndpointAuthMethodClientSecretBasic = "client_secret_basic"
	TokenEndpointAuthMethodClientSecretPost  = "client_secret_post"
)

var supportedScopeOrder = []string{
	ScopeOpenID,
	ScopeProfile,
	ScopeEmail,
	ScopeOfflineAccess,
	ScopeAPIRead,
	ScopeAPIWrite,
}

var supportedScopes = map[string]struct{}{
	ScopeOpenID:        {},
	ScopeProfile:       {},
	ScopeEmail:         {},
	ScopeOfflineAccess: {},
	ScopeAPIRead:       {},
	ScopeAPIWrite:      {},
}

var tokenEndpointAuthMethodOrder = []string{
	TokenEndpointAuthMethodNone,
	TokenEndpointAuthMethodClientSecretBasic,
	TokenEndpointAuthMethodClientSecretPost,
}

type Client struct {
	ID                      string
	Secret                  string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	AllowedScopes           []string
	TokenEndpointAuthMethod string
	RequirePKCE             bool
	Trusted                 bool
}

type AuthorizationRequest struct {
	Challenge           string
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	RequestedAt         time.Time
	ExpiresAt           time.Time
}

type AuthorizationCode struct {
	Code                string
	SubjectID           string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthenticatedAt     time.Time
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

type RefreshToken struct {
	Token           string
	SubjectID       string
	ClientID        string
	Scopes          []string
	SecurityVersion int64
	AuthenticatedAt time.Time
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

type SigningKey struct {
	ID         string
	Algorithm  string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type AuthenticatedSubject struct {
	Account         goauth.Account
	AuthenticatedAt time.Time
}

type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

type AuthorizeResult struct {
	RedirectURI string
}

type TokenRequest struct {
	GrantType        string
	Code             string
	RedirectURI      string
	CodeVerifier     string
	RefreshToken     string
	ClientID         string
	ClientSecret     string
	ClientAuthMethod string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

type RevokeRequest struct {
	Token            string
	ClientID         string
	ClientSecret     string
	ClientAuthMethod string
}

type UserInfo struct {
	Subject           string `json:"sub"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

type DiscoveryMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type OAuthError struct {
	Code        string
	Description string
	StatusCode  int
}

func (e *OAuthError) Error() string {
	if e == nil {
		return ""
	}
	if e.Description == "" {
		return e.Code
	}

	return e.Code + ": " + e.Description
}

func ParseScope(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}

	return NormalizeScopes(strings.Fields(scope))
}

func NormalizeScopes(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(raw))
	scopes := make([]string, 0, len(raw))
	for _, scope := range raw {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	slices.Sort(scopes)

	return scopes
}

func ScopeString(scopes []string) string {
	return strings.Join(NormalizeScopes(scopes), " ")
}

func HasScope(scopes []string, expected string) bool {
	for _, scope := range scopes {
		if scope == expected {
			return true
		}
	}

	return false
}

func IsSupportedScope(scope string) bool {
	_, ok := supportedScopes[scope]
	return ok
}

func SupportedScopes() []string {
	return append([]string(nil), supportedScopeOrder...)
}

func DefaultTokenEndpointAuthMethod(clientSecret string) string {
	if strings.TrimSpace(clientSecret) == "" {
		return TokenEndpointAuthMethodNone
	}

	return TokenEndpointAuthMethodClientSecretBasic
}

func NormalizeTokenEndpointAuthMethod(method, clientSecret string) string {
	switch strings.TrimSpace(method) {
	case TokenEndpointAuthMethodNone:
		return TokenEndpointAuthMethodNone
	case TokenEndpointAuthMethodClientSecretBasic:
		return TokenEndpointAuthMethodClientSecretBasic
	case TokenEndpointAuthMethodClientSecretPost:
		return TokenEndpointAuthMethodClientSecretPost
	default:
		return DefaultTokenEndpointAuthMethod(clientSecret)
	}
}

func ClientTokenEndpointAuthMethod(client Client) string {
	return NormalizeTokenEndpointAuthMethod(client.TokenEndpointAuthMethod, client.Secret)
}

func SupportedTokenEndpointAuthMethods(methods []string) []string {
	if len(methods) == 0 {
		return append([]string(nil), tokenEndpointAuthMethodOrder...)
	}

	seen := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		method = NormalizeTokenEndpointAuthMethod(method, "")
		seen[method] = struct{}{}
	}

	result := make([]string, 0, len(tokenEndpointAuthMethodOrder))
	for _, method := range tokenEndpointAuthMethodOrder {
		if _, ok := seen[method]; ok {
			result = append(result, method)
		}
	}

	if len(result) == 0 {
		return append([]string(nil), tokenEndpointAuthMethodOrder...)
	}

	return result
}
