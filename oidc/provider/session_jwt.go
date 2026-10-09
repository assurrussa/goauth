//nolint:tagliatelle // Strict OIDC claims intentionally use protocol snake_case.
package provider

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"

	"github.com/assurrussa/goauth/oidc"
)

// Precise binding times retain the persisted snapshot independently from the
// standard second-resolution auth_time claim. Applications use auth_time; only
// this provider interprets the additional session-bound authorization fields.
type sessionTokenClaims struct {
	ClientID               string                     `json:"client_id"`
	Scope                  string                     `json:"scope"`
	TokenUse               string                     `json:"token_use"`
	SessionID              string                     `json:"sid"`
	SecurityVersion        int64                      `json:"security_version"`
	FamilyID               string                     `json:"family_id"`
	PolicyStamp            string                     `json:"authorization_stamp"`
	BindingAuthenticatedAt time.Time                  `json:"binding_auth_time"`
	AbsoluteExpiresAt      time.Time                  `json:"session_expires_at"`
	ProjectID              string                     `json:"project_id"`
	AuthTime               int64                      `json:"auth_time"`
	Nonce                  string                     `json:"nonce,omitempty"`
	Email                  string                     `json:"email,omitempty"`
	EmailVerified          *bool                      `json:"email_verified,omitempty"`
	Name                   string                     `json:"name,omitempty"`
	PreferredUsername      string                     `json:"preferred_username,omitempty"`
	Profile                map[string]string          `json:"authhub_profile,omitempty"`
	Project                map[string]string          `json:"authhub_project,omitempty"`
	Identifiers            *oidc.CanonicalIdentifiers `json:"authhub_identifiers,omitempty"`
	jwt.RegisteredClaims
}

func (claims *sessionTokenClaims) binding() oidc.SessionBinding {
	return oidc.SessionBinding{
		SubjectID: claims.Subject, SecurityVersion: claims.SecurityVersion, ClientID: claims.ClientID,
		SessionID:         claims.SessionID,
		PolicyStamp:       claims.PolicyStamp,
		AuthenticatedAt:   claims.BindingAuthenticatedAt,
		AbsoluteExpiresAt: claims.AbsoluteExpiresAt,
	}
}

func (s *SessionService) prepareTokens(ctx context.Context, current oidc.SessionAdmissionResult, binding oidc.SessionBinding,
	scopes []string, nonce, familyID string,
) (*oidc.TokenResponse, oidc.SessionRefresh, time.Time, error) {
	if !validAdmission(current, &binding, s.now()) || !validSessionScopes(scopes) || !canonicalUUID(familyID) {
		return nil, oidc.SessionRefresh{}, time.Time{}, errors.New("invalid session token projection")
	}
	key, err := s.base.keys.Active(ctx)
	if err != nil {
		return nil, oidc.SessionRefresh{}, time.Time{}, err
	}
	// Match the strict verifier before preparing any result or one-time writes.
	if !boundedASCII(key.ID, 256) {
		return nil, oidc.SessionRefresh{}, time.Time{}, errors.New("invalid session signing key id")
	}
	now := s.now()
	deadline := minTime(now.Add(5*time.Minute), binding.AbsoluteExpiresAt).Truncate(time.Second)
	if !now.Before(deadline) {
		return nil, oidc.SessionRefresh{}, time.Time{}, errSessionExpired
	}
	claims := sessionTokenClaims{
		ClientID: binding.ClientID, Scope: oidc.ScopeString(scopes), TokenUse: tokenUseAccess,
		SessionID: binding.SessionID, SecurityVersion: binding.SecurityVersion, FamilyID: familyID,
		PolicyStamp: binding.PolicyStamp, BindingAuthenticatedAt: binding.AuthenticatedAt, AbsoluteExpiresAt: binding.AbsoluteExpiresAt,
		ProjectID: current.Projection.ProjectID, AuthTime: binding.AuthenticatedAt.Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: s.base.issuer, Subject: binding.SubjectID, Audience: jwt.ClaimStrings{binding.ClientID},
			ExpiresAt: jwt.NewNumericDate(deadline), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		},
	}
	access, err := s.base.signToken(key, claims, "at+jwt")
	if err != nil {
		return nil, oidc.SessionRefresh{}, time.Time{}, err
	}
	claims.TokenUse = tokenUseID
	claims.Nonce = nonce
	info := s.userInfo(current, scopes)
	claims.Email = info.Email
	claims.EmailVerified = info.EmailVerified
	claims.Name = info.Name
	claims.PreferredUsername = info.PreferredUsername
	claims.Profile = info.Profile
	claims.Project = info.Project
	claims.Identifiers = info.Identifiers
	id, err := s.base.signToken(key, claims, "JWT")
	if err != nil {
		return nil, oidc.SessionRefresh{}, time.Time{}, err
	}
	raw, err := s.base.generateToken()
	if err != nil {
		return nil, oidc.SessionRefresh{}, time.Time{}, err
	}
	if !s.now().Before(deadline) || !validBinding(binding, s.now()) {
		return nil, oidc.SessionRefresh{}, time.Time{}, errSessionExpired
	}
	next := oidc.SessionRefresh{RefreshToken: oidc.RefreshToken{
		Token: raw, SubjectID: binding.SubjectID, ClientID: binding.ClientID,
		Scopes: oidc.NormalizeScopes(scopes), SecurityVersion: binding.SecurityVersion, AuthenticatedAt: binding.AuthenticatedAt,
		CreatedAt: now, ExpiresAt: binding.AbsoluteExpiresAt,
	}, Binding: binding, FamilyID: familyID}
	return &oidc.TokenResponse{
		AccessToken: access, IDToken: id, RefreshToken: raw, TokenType: "Bearer",
		ExpiresIn: int64(deadline.Sub(now).Seconds()), Scope: claims.Scope,
	}, next, deadline, nil
}

func (s *SessionService) parseSessionAccessToken(ctx context.Context, raw string) (*sessionTokenClaims, error) {
	if len(raw) == 0 || len(raw) > 32768 {
		return nil, errors.New("invalid token length")
	}
	claims := &sessionTokenClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		typ, typed := token.Header["typ"].(string)
		if !ok || !boundedASCII(kid, 256) || !typed || typ != "at+jwt" {
			return nil, errors.New("required key id and access token type")
		}
		key, err := s.base.keys.Get(ctx, kid)
		if err != nil {
			return nil, err
		}
		if key.ID != kid || (key.Algorithm != "" && key.Algorithm != jwt.SigningMethodRS256.Alg()) {
			return nil, errors.New("signing key mismatch")
		}
		if err := oidc.ValidateRSAPublicKey(key.PublicKey); err != nil {
			return nil, err
		}
		return key.PublicKey, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(s.base.issuer),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.now), jwt.WithStrictDecoding())
	if err != nil {
		return nil, err
	}
	if !parsed.Valid || claims.TokenUse != tokenUseAccess || !validBinding(claims.binding(), s.now()) ||
		!canonicalUUID(claims.ProjectID) ||
		!canonicalUUID(claims.FamilyID) ||
		len(claims.Audience) != 1 ||
		claims.Audience[0] != claims.ClientID ||

		claims.IssuedAt == nil || claims.NotBefore == nil || !claims.NotBefore.Equal(claims.IssuedAt.Time) ||
		claims.ExpiresAt.After(claims.IssuedAt.Add(5*time.Minute)) || !claims.ExpiresAt.After(claims.IssuedAt.Time) ||
		claims.ExpiresAt.After(claims.AbsoluteExpiresAt) || claims.AuthTime != claims.BindingAuthenticatedAt.Unix() ||
		!validSessionScopes(oidc.ParseScope(claims.Scope)) || oidc.ScopeString(oidc.ParseScope(claims.Scope)) != claims.Scope {
		return nil, errors.New("invalid session token claims")
	}
	return claims, nil
}

func (s *SessionService) userInfo(current oidc.SessionAdmissionResult, scopes []string) oidc.SessionUserInfo {
	result := oidc.SessionUserInfo{UserInfo: s.base.buildUserInfo(current.Account, scopes), ProjectID: current.Projection.ProjectID}
	if oidc.HasScope(scopes, oidc.ScopeProfile) {
		if current.Projection.Identifiers != nil {
			identifiers := *current.Projection.Identifiers
			result.Identifiers = &identifiers
		}
		result.Profile = maps.Clone(current.Projection.Profile)
		result.Project = maps.Clone(current.Projection.Project)
	}
	return result
}

func validProjection(value oidc.SessionProjection) bool {
	return canonicalUUID(value.ProjectID) && validMetadataMap(value.Profile) && validMetadataMap(value.Project) &&
		validCanonicalIdentifiers(value.Identifiers)
}

var (
	canonicalLoginPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	canonicalAliasPattern = regexp.MustCompile("^[a-z0-9!#$%&'*+/=?^_`{|}~-]+([.][a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@" +
		"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
)

func validCanonicalIdentifiers(value *oidc.CanonicalIdentifiers) bool {
	if value == nil {
		return true // Existing hosts need not opt in to this claim.
	}
	if value.Version != 1 || !canonicalLoginPattern.MatchString(value.Login) {
		return false
	}
	alias := value.EmailAlias
	return alias == "" || len(alias) <= 254 && strings.IndexByte(alias, '@') <= 64 && canonicalAliasPattern.MatchString(alias)
}

func validMetadataMap(value map[string]string) bool {
	if len(value) > 8 {
		return false
	}
	size := 0
	for key, item := range value {
		if len(key) == 0 || len(key) > 32 || len(item) > 256 || !utf8.ValidString(item) || reservedSessionMetadata(key) {
			return false
		}
		for i := range len(key) {
			c := key[i]
			letter := c >= 'a' && c <= 'z'
			suffix := i > 0 && (c >= '0' && c <= '9' || c == '_')
			if !letter && !suffix {
				return false
			}
		}
		if strings.ContainsFunc(item, unicode.IsControl) {
			return false
		}
		size += len(key) + len(item)
	}
	return size <= 2048
}

func reservedSessionMetadata(key string) bool {
	const reserved = "sub iss aud exp iat nbf jti nonce auth_time azp acr amr at_hash c_hash sid " +
		"client_id project_id subject_id security_version access_version profile_version metadata_version scope scopes " +
		"role roles permission permissions groups entitlements password password_hash password_phc secret client_secret " +
		"api_key access_token refresh_token id_token token credential credentials email_verified phone_number_verified " +
		"enabled active disabled retired"
	if slices.Contains(strings.Fields(reserved), key) {
		return true
	}
	for _, prefix := range []string{
		"auth_",
		"oauth_",
		"oidc_",
		"jwt_",
		"token_",
		"secret_",
		"password_",
		"credential_",
		"role_",
		"permission_",
		"scope_",
		"session_",
		"security_",
	} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
