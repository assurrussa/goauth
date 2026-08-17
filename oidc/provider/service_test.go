//nolint:testpackage // Tests need same-package access to provider internals and direct JWT parsing.
package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
)

const (
	concurrentAuthorizationCode = "concurrent-code"
	testProviderIssuer          = "https://api.example.com"
)

func TestAuthorizeUnauthenticatedRedirectsToHostedLogin(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)
	discovery := h.service.Discovery(context.Background())
	require.Equal(t, testProviderIssuer, discovery.Issuer)
	require.Equal(t, "https://api.example.com/oauth2/token", discovery.TokenEndpoint)
	require.Contains(t, discovery.ScopesSupported, oidc.ScopeAPIRead)
	require.Contains(t, discovery.ScopesSupported, oidc.ScopeAPIWrite)

	jwks, err := h.service.JWKS(context.Background())
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "kid-1", jwks.Keys[0].Kid)

	result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID:            h.client.ID,
		RedirectURI:         h.client.RedirectURIs[0],
		ResponseType:        "code", //nolint:goconst // autofix
		Scope:               "openid profile email offline_access",
		State:               "state-1", //nolint:goconst // autofix
		Nonce:               "nonce-1",
		CodeChallenge:       codeChallengeFor("verifier-1"),
		CodeChallengeMethod: "S256", //nolint:goconst // autofix
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "https://front.example.com/login?oidc_challenge=challenge-1", result.RedirectURI)

	record, err := h.requests.Get(context.Background(), "challenge-1")
	require.NoError(t, err)
	require.Equal(t, h.client.ID, record.ClientID)
	require.Equal(t, "state-1", record.State)
	require.Equal(t, "nonce-1", record.Nonce)
	require.Equal(t, []string{oidc.ScopeEmail, oidc.ScopeOfflineAccess, oidc.ScopeOpenID, oidc.ScopeProfile}, record.Scopes)
}

func TestProviderRejectsOfflineAccessTTLAboveFiveMinutes(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)
	_, err := New(Options{
		Clients:        h.service.clients,
		Requests:       h.requests,
		Codes:          h.codes,
		RefreshTokens:  h.refreshTokens,
		Keys:           h.keys,
		Claims:         h.service.claims,
		Issuer:         testProviderIssuer,
		AccessTokenTTL: 5*time.Minute + time.Second,
	})
	require.EqualError(t, err, "OIDC access token TTL must not exceed 5m0s")
}

func TestProviderConstructorAndDisabledMode(t *testing.T) {
	t.Parallel()
	disabled := NewDisabled()
	require.False(t, disabled.Enabled())
	keys, err := disabled.JWKS(context.Background())
	require.NoError(t, err)
	require.Empty(t, keys.Keys)

	h := newOIDCTestHarness(t)
	base := Options{
		Clients:       h.service.clients,
		Requests:      h.requests,
		Codes:         h.codes,
		RefreshTokens: h.refreshTokens,
		Keys:          h.keys,
		Claims:        h.service.claims,
		Issuer:        testProviderIssuer,
	}
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"clients", func(options *Options) { options.Clients = nil }},
		{"requests", func(options *Options) { options.Requests = nil }},
		{"codes", func(options *Options) { options.Codes = nil }},
		{"refresh", func(options *Options) { options.RefreshTokens = nil }},
		{"keys", func(options *Options) { options.Keys = nil }},
		{"claims", func(options *Options) { options.Claims = nil }},
		{"issuer", func(options *Options) { options.Issuer = "" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			options := base
			testCase.mutate(&options)
			_, err := New(options)
			require.Error(t, err)
		})
	}
	require.Panics(t, func() { Must(Options{}) })
}

func TestProviderRejectsInvalidProtocolInputs(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)

	_, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{GrantType: "client_credentials"})
	requireOAuthError(t, err, "unsupported_grant_type")
	_, err = h.service.UserInfo(context.Background(), "not-a-token")
	requireOAuthError(t, err, "invalid_token")
	err = h.service.Revoke(context.Background(), oidc.RevokeRequest{})
	requireOAuthError(t, err, "invalid_request")
	err = h.service.Revoke(context.Background(), oidc.RevokeRequest{Token: "missing", ClientID: h.client.ID})
	require.NoError(t, err)

	_, err = h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID: h.client.ID, RedirectURI: "https://attacker.example.test/callback",
	}, nil)
	requireOAuthError(t, err, "invalid_request")
	result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0], ResponseType: "token", Scope: oidc.ScopeOpenID,
	}, nil)
	require.NoError(t, err)
	require.Contains(t, result.RedirectURI, "error=unsupported_response_type")

	require.NoError(t, h.codes.Save(context.Background(), oidc.AuthorizationCode{
		Code:                "wrong-pkce",
		SubjectID:           h.subject.Subject.ID.String(),
		ClientID:            h.client.ID,
		RedirectURI:         h.client.RedirectURIs[0],
		Scopes:              []string{oidc.ScopeOpenID},
		CodeChallenge:       codeChallengeFor("right-verifier"),
		CodeChallengeMethod: "S256",
		AuthenticatedAt:     h.now,
		CreatedAt:           h.now,
		ExpiresAt:           h.now.Add(time.Minute),
	}))
	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeAuthorizationCode, Code: "wrong-pkce", RedirectURI: h.client.RedirectURIs[0],
		CodeVerifier: "wrong-verifier", ClientID: h.client.ID,
	})
	requireOAuthError(t, err, "invalid_grant")
}

func TestProviderRejectsExpiredChallengeAndSecurityVersionChange(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	require.NoError(t, h.requests.Save(context.Background(), oidc.AuthorizationRequest{
		Challenge: "expired", ClientID: h.client.ID, RedirectURI: h.client.RedirectURIs[0],
		Scopes: []string{oidc.ScopeOpenID}, ExpiresAt: h.now.Add(-time.Second),
	}))
	_, err := h.service.ContinueAuthorization(context.Background(), "expired", nil)
	requireOAuthError(t, err, "invalid_request")

	h.refreshTokens.items["old-version"] = oidc.RefreshToken{
		Token:           "old-version",
		SubjectID:       h.subject.Subject.ID.String(),
		ClientID:        h.client.ID,
		Scopes:          []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
		SecurityVersion: h.subject.Subject.SecurityVersion - 1,
		AuthenticatedAt: h.now,
		CreatedAt:       h.now,
		ExpiresAt:       h.now.Add(time.Hour),
	}
	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType: grantTypeRefreshToken, RefreshToken: "old-version", ClientID: h.client.ID,
	})
	requireOAuthError(t, err, "invalid_grant")
}

func TestAuthorizationCodeExchangeAndUserInfo(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)

	authorizeResult, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID:            h.client.ID,
		RedirectURI:         h.client.RedirectURIs[0],
		ResponseType:        "code",
		Scope:               "openid profile email offline_access",
		State:               "state-1",
		Nonce:               "nonce-1",
		CodeChallenge:       codeChallengeFor("verifier-1"),
		CodeChallengeMethod: "S256",
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "https://front.example.com/login?oidc_challenge=challenge-1", authorizeResult.RedirectURI)

	current := &oidc.AuthenticatedSubject{
		Account:         h.subject,
		AuthenticatedAt: h.now.Add(-2 * time.Minute),
	}
	continueResult, err := h.service.ContinueAuthorization(context.Background(), "challenge-1", current)
	require.NoError(t, err)
	require.Equal(t, "https://client.example.com/callback?code=code-1&state=state-1", continueResult.RedirectURI)

	response, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:    grantTypeAuthorizationCode,
		Code:         "code-1", //nolint:goconst // autofix
		RedirectURI:  h.client.RedirectURIs[0],
		CodeVerifier: "verifier-1",
		ClientID:     h.client.ID,
	})
	require.NoError(t, err)
	require.NotEmpty(t, response.AccessToken)
	require.NotEmpty(t, response.IDToken)
	require.Equal(t, "refresh-1", response.RefreshToken)
	require.Equal(t, "Bearer", response.TokenType)
	require.Equal(t, int64((5 * time.Minute).Seconds()), response.ExpiresIn)
	require.Equal(t, "email offline_access openid profile", response.Scope)

	idClaims := &idTokenClaims{}
	parsed, err := jwt.ParseWithClaims(response.IDToken, idClaims, func(_ *jwt.Token) (any, error) {
		active, keyErr := h.keys.Active(context.Background())
		if keyErr != nil {
			return nil, keyErr
		}
		return active.PublicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.Equal(t, h.subject.Subject.ID.String(), idClaims.Subject)
	require.Equal(t, "nonce-1", idClaims.Nonce)
	require.Equal(t, current.AuthenticatedAt.Unix(), idClaims.AuthTime)
	require.NotNil(t, idClaims.EmailVerified)
	require.False(t, *idClaims.EmailVerified)

	info, err := h.service.UserInfo(context.Background(), response.AccessToken)
	require.NoError(t, err)
	require.Equal(t, h.subject.Subject.ID.String(), info.Subject)
	require.Equal(t, h.subject.PrimaryEmail.DisplayValue, info.Email)
	require.Equal(t, h.subject.Profile.DisplayName, info.Name)
	require.Equal(t, h.subject.Profile.Username, info.PreferredUsername)
	require.NotNil(t, info.EmailVerified)
	require.False(t, *info.EmailVerified)

	refreshRecord, err := h.refreshTokens.Get(context.Background(), "refresh-1")
	require.NoError(t, err)
	require.Equal(t, h.subject.Subject.ID.String(), refreshRecord.SubjectID)
	require.Equal(t, int64(7), refreshRecord.SecurityVersion)
}

func TestEmailVerifiedClaimUsesConfirmationState(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)
	confirmedAt := h.now.Add(-time.Minute)
	subject := h.subject
	subject.PrimaryEmail.VerifiedAt = &confirmedAt
	idToken, err := h.service.signIDToken(
		context.Background(),
		subject,
		h.client.ID,
		[]string{oidc.ScopeOpenID, oidc.ScopeEmail},
		h.now,
		"nonce",
	)
	require.NoError(t, err)
	claims := &idTokenClaims{}
	parsed, err := jwt.ParseWithClaims(idToken, claims, func(_ *jwt.Token) (any, error) {
		active, keyErr := h.keys.Active(context.Background())
		if keyErr != nil {
			return nil, keyErr
		}
		return active.PublicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.NotNil(t, claims.EmailVerified)
	require.True(t, *claims.EmailVerified)

	info := h.service.buildUserInfo(subject, []string{oidc.ScopeOpenID, oidc.ScopeEmail})
	require.NotNil(t, info.EmailVerified)
	require.True(t, *info.EmailVerified)
}

func TestAuthorizationCodeConsumeIsAtomic(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)
	require.NoError(t, h.codes.Save(context.Background(), oidc.AuthorizationCode{
		Code:                concurrentAuthorizationCode,
		SubjectID:           h.subject.Subject.ID.String(),
		ClientID:            h.client.ID,
		RedirectURI:         h.client.RedirectURIs[0],
		Scopes:              []string{oidc.ScopeOpenID},
		CodeChallenge:       codeChallengeFor("concurrent-verifier"),
		CodeChallengeMethod: "S256",
		AuthenticatedAt:     h.now.Add(-time.Minute),
		CreatedAt:           h.now,
		ExpiresAt:           h.now.Add(time.Minute),
	}))

	const exchanges = 32
	var successes atomic.Int64
	var invalidGrants atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range exchanges {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
				GrantType:    grantTypeAuthorizationCode,
				Code:         concurrentAuthorizationCode,
				RedirectURI:  h.client.RedirectURIs[0],
				CodeVerifier: "concurrent-verifier",
				ClientID:     h.client.ID,
			})
			if err == nil {
				successes.Add(1)
				return
			}
			var oauthErr *oidc.OAuthError
			if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
				invalidGrants.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()

	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, exchanges-1, invalidGrants.Load())
}

func TestAuthorizationChallengeConsumeIsAtomic(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)
	h.service.generateToken = func() (string, error) { return concurrentAuthorizationCode, nil }
	require.NoError(t, h.requests.Save(context.Background(), oidc.AuthorizationRequest{
		Challenge:           "concurrent-challenge",
		ClientID:            h.client.ID,
		RedirectURI:         h.client.RedirectURIs[0],
		State:               "state",
		Scopes:              []string{oidc.ScopeOpenID},
		CodeChallenge:       codeChallengeFor("concurrent-verifier"),
		CodeChallengeMethod: "S256",
		RequestedAt:         h.now,
		ExpiresAt:           h.now.Add(time.Minute),
	}))
	current := &oidc.AuthenticatedSubject{Account: h.subject, AuthenticatedAt: h.now}

	const continuations = 32
	var successes atomic.Int64
	var invalidRequests atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range continuations {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := h.service.ContinueAuthorization(context.Background(), "concurrent-challenge", current)
			if err == nil {
				successes.Add(1)
				return
			}
			var oauthErr *oidc.OAuthError
			if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_request" {
				invalidRequests.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()

	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, continuations-1, invalidRequests.Load())
}

func TestRefreshRotationAndRevoke(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)
	h.service.generateToken = (&tokenGenerator{tokens: []string{"refresh-2"}}).Next //nolint:goconst // autofix
	h.refreshTokens.items["refresh-1"] = oidc.RefreshToken{
		Token:           "refresh-1", //nolint:goconst // autofix
		SubjectID:       h.subject.Subject.ID.String(),
		ClientID:        h.client.ID,
		Scopes:          []string{oidc.ScopeEmail, oidc.ScopeOfflineAccess, oidc.ScopeOpenID, oidc.ScopeProfile},
		SecurityVersion: h.subject.Subject.SecurityVersion,
		AuthenticatedAt: h.now.Add(-2 * time.Minute),
		CreatedAt:       h.now.Add(-time.Minute),
		ExpiresAt:       h.now.Add(time.Hour),
	}

	response, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: "refresh-1",
		ClientID:     h.client.ID,
	})
	require.NoError(t, err)
	require.Equal(t, "refresh-2", response.RefreshToken)

	rotated, err := h.refreshTokens.Get(context.Background(), "refresh-2")
	require.NoError(t, err)
	require.NotNil(t, h.refreshTokens.items["refresh-1"].RevokedAt)
	require.Equal(t, rotated.SubjectID, h.subject.Subject.ID.String())

	err = h.service.Revoke(context.Background(), oidc.RevokeRequest{
		Token:    "refresh-2",
		ClientID: h.client.ID,
	})
	require.NoError(t, err)
	require.NotNil(t, h.refreshTokens.items["refresh-2"].RevokedAt)

	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:    grantTypeRefreshToken,
		RefreshToken: "refresh-2",
		ClientID:     h.client.ID,
	})
	var oauthErr *oidc.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	require.Equal(t, "invalid_grant", oauthErr.Code)
}

func TestRefreshRotationAllowsExactlyOneConcurrentExchange(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)
	h.refreshTokens.items["refresh-concurrent"] = oidc.RefreshToken{
		Token:           "refresh-concurrent",
		SubjectID:       h.subject.Subject.ID.String(),
		ClientID:        h.client.ID,
		Scopes:          []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
		SecurityVersion: h.subject.Subject.SecurityVersion,
		AuthenticatedAt: h.now.Add(-time.Minute),
		CreatedAt:       h.now,
		ExpiresAt:       h.now.Add(time.Hour),
	}
	var tokenSequence atomic.Int64
	h.service.generateToken = func() (string, error) {
		return fmt.Sprintf("refresh-next-%d", tokenSequence.Add(1)), nil
	}

	const exchanges = 32
	var successes atomic.Int64
	var invalidGrants atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range exchanges {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
				GrantType:    grantTypeRefreshToken,
				RefreshToken: "refresh-concurrent",
				ClientID:     h.client.ID,
			})
			if err == nil {
				successes.Add(1)
				return
			}
			var oauthErr *oidc.OAuthError
			if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
				invalidGrants.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()

	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, exchanges-1, invalidGrants.Load())
}

func TestAuthorizationCodeFlowSupportsAPIScope(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarnessWithClient(t, oidc.Client{
		ID:            "oidc-demo",
		RedirectURIs:  []string{"https://client.example.com/callback"}, //nolint:goconst // autofix
		AllowedScopes: []string{oidc.ScopeAPIRead, oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
		RequirePKCE:   true,
		Trusted:       true,
	})

	result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID:            h.client.ID,
		RedirectURI:         h.client.RedirectURIs[0],
		ResponseType:        "code",
		Scope:               "openid offline_access api:read",
		State:               "state-api",
		CodeChallenge:       codeChallengeFor("verifier-api"),
		CodeChallengeMethod: "S256",
	}, nil)
	require.NoError(t, err)
	require.Equal(t, "https://front.example.com/login?oidc_challenge=challenge-1", result.RedirectURI)

	current := &oidc.AuthenticatedSubject{
		Account:         h.subject,
		AuthenticatedAt: h.now.Add(-time.Minute),
	}
	continueResult, err := h.service.ContinueAuthorization(context.Background(), "challenge-1", current)
	require.NoError(t, err)
	require.Equal(t, "https://client.example.com/callback?code=code-1&state=state-api", continueResult.RedirectURI)

	response, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:    grantTypeAuthorizationCode,
		Code:         "code-1",
		RedirectURI:  h.client.RedirectURIs[0],
		CodeVerifier: "verifier-api",
		ClientID:     h.client.ID,
	})
	require.NoError(t, err)
	require.Equal(t, "api:read offline_access openid", response.Scope)

	record, err := h.refreshTokens.Get(context.Background(), response.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, []string{oidc.ScopeAPIRead, oidc.ScopeOfflineAccess, oidc.ScopeOpenID}, record.Scopes)
}

func TestAuthorizeRejectsScopeOutsideClientPolicy(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)

	result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID:            h.client.ID,
		RedirectURI:         h.client.RedirectURIs[0],
		ResponseType:        "code",
		Scope:               "openid api:read",
		State:               "state-1",
		CodeChallenge:       codeChallengeFor("verifier-1"),
		CodeChallengeMethod: "S256",
	}, nil)
	require.NoError(t, err)
	require.Equal(
		t,
		"https://client.example.com/callback?error=invalid_scope&error_description=scope+is+not+allowed+for+this+client&state=state-1",
		result.RedirectURI,
	)
}

func TestRefreshTokenRejectsWrongClientAuthMethod(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarnessWithClient(t, oidc.Client{
		ID:            "confidential-basic",
		Secret:        "top-secret",
		RedirectURIs:  []string{"https://client.example.com/callback"},
		AllowedScopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
		RequirePKCE:   true,
		Trusted:       true,
	})
	h.refreshTokens.items["refresh-1"] = oidc.RefreshToken{
		Token:           "refresh-1",
		SubjectID:       h.subject.Subject.ID.String(),
		ClientID:        h.client.ID,
		Scopes:          []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
		SecurityVersion: h.subject.Subject.SecurityVersion,
		AuthenticatedAt: h.now.Add(-2 * time.Minute),
		CreatedAt:       h.now.Add(-time.Minute),
		ExpiresAt:       h.now.Add(time.Hour),
	}

	_, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:        grantTypeRefreshToken,
		RefreshToken:     "refresh-1",
		ClientID:         h.client.ID,
		ClientAuthMethod: oidc.TokenEndpointAuthMethodNone,
	})
	var oauthErr *oidc.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	require.Equal(t, "invalid_client", oauthErr.Code)

	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:        grantTypeRefreshToken,
		RefreshToken:     "refresh-1",
		ClientID:         h.client.ID,
		ClientSecret:     h.client.Secret,
		ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
	})
	require.NoError(t, err)
}

func TestRefreshTokenSupportsClientSecretPost(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarnessWithClient(t, oidc.Client{
		ID:                      "confidential-post",
		Secret:                  "top-secret",
		RedirectURIs:            []string{"https://client.example.com/callback"},
		AllowedScopes:           []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess},
		TokenEndpointAuthMethod: oidc.TokenEndpointAuthMethodClientSecretPost,
		RequirePKCE:             true,
		Trusted:                 true,
	})
	h.refreshTokens.items["refresh-1"] = oidc.RefreshToken{
		Token:           "refresh-1",
		SubjectID:       h.subject.Subject.ID.String(),
		ClientID:        h.client.ID,
		Scopes:          []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
		SecurityVersion: h.subject.Subject.SecurityVersion,
		AuthenticatedAt: h.now.Add(-2 * time.Minute),
		CreatedAt:       h.now.Add(-time.Minute),
		ExpiresAt:       h.now.Add(time.Hour),
	}

	_, err := h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:        grantTypeRefreshToken,
		RefreshToken:     "refresh-1",
		ClientID:         h.client.ID,
		ClientSecret:     h.client.Secret,
		ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
	})
	var oauthErr *oidc.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	require.Equal(t, "invalid_client", oauthErr.Code)

	_, err = h.service.ExchangeToken(context.Background(), oidc.TokenRequest{
		GrantType:        grantTypeRefreshToken,
		RefreshToken:     "refresh-1",
		ClientID:         h.client.ID,
		ClientSecret:     h.client.Secret,
		ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretPost,
	})
	require.NoError(t, err)
}

func TestJWKSIncludesNextKeyAndOldTokensStillValidate(t *testing.T) {
	t.Parallel()

	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	oldStore, err := newMemoryKeyStore("kid-old", oldKey)
	require.NoError(t, err)

	oldHarness := newOIDCTestHarnessWithKeyStore(t, oidc.Client{
		ID:            "pet-app",
		RedirectURIs:  []string{"https://client.example.com/callback"},
		AllowedScopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
		RequirePKCE:   true,
		Trusted:       true,
	}, oldStore)
	oldResponse, err := oldHarness.service.issueTokens(
		context.Background(),
		oldHarness.subject,
		oldHarness.client,
		[]string{oidc.ScopeOpenID, oidc.ScopeEmail},
		oldHarness.now.Add(-time.Minute),
		"",
		"",
	)
	require.NoError(t, err)

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rotatedStore, err := newMemoryKeyStore("kid-new", newKey, memoryKeyCandidate{
		keyID:      "kid-old",
		privateKey: oldKey,
	})
	require.NoError(t, err)
	rotatedHarness := newOIDCTestHarnessWithKeyStore(t, oldHarness.client, rotatedStore)
	rotatedHarness.subject = oldHarness.subject
	rotatedHarness.service.claims = &memoryClaimsResolver{
		items: map[string]goauth.Account{
			oldHarness.subject.Subject.ID.String(): oldHarness.subject,
		},
	}

	jwks, err := rotatedHarness.service.JWKS(context.Background())
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 2)
	require.Equal(t, "kid-new", jwks.Keys[0].Kid)
	require.Equal(t, "kid-old", jwks.Keys[1].Kid)

	info, err := rotatedHarness.service.UserInfo(context.Background(), oldResponse.AccessToken)
	require.NoError(t, err)
	require.Equal(t, oldHarness.subject.Subject.ID.String(), info.Subject)

	newResponse, err := rotatedHarness.service.issueTokens(
		context.Background(),
		oldHarness.subject,
		rotatedHarness.client,
		[]string{oidc.ScopeOpenID},
		rotatedHarness.now.Add(-time.Minute),
		"",
		"",
	)
	require.NoError(t, err)

	claims := &accessTokenClaims{}
	parsed, err := jwt.ParseWithClaims(newResponse.AccessToken, claims, func(_ *jwt.Token) (any, error) {
		active, keyErr := rotatedStore.Active(context.Background())
		if keyErr != nil {
			return nil, keyErr
		}
		return active.PublicKey, nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
}

func TestAuthorizeRequiresPKCE(t *testing.T) {
	t.Parallel()

	h := newOIDCTestHarness(t)

	result, err := h.service.Authorize(context.Background(), oidc.AuthorizeRequest{
		ClientID:     h.client.ID,
		RedirectURI:  h.client.RedirectURIs[0],
		ResponseType: "code",
		Scope:        "openid",
		State:        "state-1",
	}, nil)
	require.NoError(t, err)
	expectedRedirect := "https://client.example.com/callback?" +
		"error=invalid_request&error_description=code_challenge+is+required&state=state-1"
	require.Equal(t, expectedRedirect, result.RedirectURI)
}

func TestCodeVerifierRejectsMalformedInputs(t *testing.T) {
	t.Parallel()
	require.False(t, verifyCodeVerifier("", "challenge"))
	require.False(t, subtleStringCompare("a", "different-length"))
}

type oidcTestHarness struct {
	service       *Service
	client        oidc.Client
	subject       goauth.Account
	requests      *memoryRequestStore
	codes         *memoryCodeStore
	refreshTokens *memoryRefreshStore
	keys          *memoryKeyStore
	now           time.Time
}

func newOIDCTestHarness(t *testing.T) *oidcTestHarness {
	t.Helper()

	client := oidc.Client{
		ID:            "pet-app",
		RedirectURIs:  []string{"https://client.example.com/callback"},
		AllowedScopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess},
		RequirePKCE:   true,
		Trusted:       true,
	}

	return newOIDCTestHarnessWithClient(t, client)
}

func newOIDCTestHarnessWithClient(t *testing.T, client oidc.Client) *oidcTestHarness {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keys, err := newMemoryKeyStore("kid-1", key)
	require.NoError(t, err)

	return newOIDCTestHarnessWithKeyStoreAndNow(t, client, keys, now)
}

func newOIDCTestHarnessWithKeyStore(t *testing.T, client oidc.Client, keys *memoryKeyStore) *oidcTestHarness {
	t.Helper()

	return newOIDCTestHarnessWithKeyStoreAndNow(t, client, keys, time.Now().UTC().Truncate(time.Second))
}

func newOIDCTestHarnessWithKeyStoreAndNow(
	t *testing.T,
	client oidc.Client,
	keys *memoryKeyStore,
	now time.Time,
) *oidcTestHarness {
	t.Helper()

	subjectID := goauth.NewSubjectID()
	subject := goauth.Account{
		Subject: goauth.Subject{
			ID:              subjectID,
			Status:          goauth.SubjectStatusActive,
			SecurityVersion: 7,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		PrimaryEmail: goauth.Identifier{
			ID:              "email-1",
			SubjectID:       subjectID,
			Scheme:          goauth.IdentifierSchemeEmail,
			DisplayValue:    "user@example.com",
			NormalizedValue: "user@example.com",
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		Profile: goauth.BasicProfile{DisplayName: "Test User", Username: "tester"},
	}

	requests := &memoryRequestStore{items: make(map[string]oidc.AuthorizationRequest)}
	codes := &memoryCodeStore{items: make(map[string]oidc.AuthorizationCode)}
	refreshTokens := &memoryRefreshStore{items: make(map[string]oidc.RefreshToken)}
	claims := &memoryClaimsResolver{items: map[string]goauth.Account{subject.Subject.ID.String(): subject}}

	generator := &tokenGenerator{tokens: []string{"challenge-1", "code-1", "refresh-1", "refresh-2"}}
	service, err := New(Options{
		Clients:                  &memoryClientStore{items: map[string]oidc.Client{client.ID: client}},
		Requests:                 requests,
		Codes:                    codes,
		RefreshTokens:            refreshTokens,
		Keys:                     keys,
		Claims:                   claims,
		Issuer:                   testProviderIssuer,
		FrontendLoginURL:         "https://front.example.com/login",
		TokenEndpointAuthMethods: oidc.SupportedTokenEndpointAuthMethods([]string{oidc.ClientTokenEndpointAuthMethod(client)}),
		RequestTTL:               10 * time.Minute,
		CodeTTL:                  5 * time.Minute,
		AccessTokenTTL:           5 * time.Minute,
		RefreshTokenTTL:          24 * time.Hour,
		Now:                      func() time.Time { return now },
		GenerateToken:            generator.Next,
	})
	require.NoError(t, err)

	return &oidcTestHarness{
		service:       service,
		client:        client,
		subject:       subject,
		requests:      requests,
		codes:         codes,
		refreshTokens: refreshTokens,
		keys:          keys,
		now:           now,
	}
}

type tokenGenerator struct {
	tokens []string
	index  int
}

func (g *tokenGenerator) Next() (string, error) {
	if g.index >= len(g.tokens) {
		return "", errors.New("token generator exhausted")
	}

	token := g.tokens[g.index]
	g.index++

	return token, nil
}

type memoryClientStore struct {
	items map[string]oidc.Client
}

func (s *memoryClientStore) Get(_ context.Context, clientID string) (oidc.Client, error) {
	return s.items[clientID], nil
}

type memoryRequestStore struct {
	mu    sync.Mutex
	items map[string]oidc.AuthorizationRequest
}

func (s *memoryRequestStore) Save(_ context.Context, request oidc.AuthorizationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[request.Challenge] = request
	return nil
}

func (s *memoryRequestStore) Get(_ context.Context, challenge string) (oidc.AuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.items[challenge]
	if !ok {
		return oidc.AuthorizationRequest{}, oidc.ErrAuthorizationRequestNotFound
	}
	return request, nil
}

func (s *memoryRequestStore) Consume(_ context.Context, challenge string) (oidc.AuthorizationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.items[challenge]
	if !ok {
		return oidc.AuthorizationRequest{}, oidc.ErrAuthorizationRequestNotFound
	}
	delete(s.items, challenge)
	return request, nil
}

type memoryCodeStore struct {
	mu    sync.Mutex
	items map[string]oidc.AuthorizationCode
}

func (s *memoryCodeStore) Save(_ context.Context, code oidc.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[code.Code] = code
	return nil
}

func (s *memoryCodeStore) Consume(_ context.Context, code string) (oidc.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.items[code]
	if !ok {
		return oidc.AuthorizationCode{}, oidc.ErrAuthorizationCodeNotFound
	}
	delete(s.items, code)
	return record, nil
}

type memoryRefreshStore struct {
	mu    sync.Mutex
	items map[string]oidc.RefreshToken
}

func (s *memoryRefreshStore) Save(_ context.Context, token oidc.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[token.Token] = token
	return nil
}

func (s *memoryRefreshStore) Get(_ context.Context, token string) (oidc.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.items[token]
	if !ok {
		return oidc.RefreshToken{}, oidc.ErrRefreshTokenNotFound
	}
	return record, nil
}

func (s *memoryRefreshStore) Revoke(_ context.Context, token string, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.items[token]
	if !ok {
		return oidc.ErrRefreshTokenNotFound
	}
	record.RevokedAt = &revokedAt
	s.items[token] = record
	return nil
}

func (s *memoryRefreshStore) Rotate(_ context.Context, currentToken string, next oidc.RefreshToken, revokedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.items[currentToken]
	if !ok || current.RevokedAt != nil {
		return oidc.ErrRefreshTokenNotFound
	}
	current.RevokedAt = &revokedAt
	s.items[currentToken] = current
	s.items[next.Token] = next
	return nil
}

type memoryKeyStore struct {
	activeID string
	keys     map[string]oidc.SigningKey
	jwks     []oidc.JWK
}

type memoryKeyCandidate struct {
	keyID      string
	privateKey *rsa.PrivateKey
}

func newMemoryKeyStore(
	activeKeyID string,
	activePrivateKey *rsa.PrivateKey,
	extra ...memoryKeyCandidate,
) (*memoryKeyStore, error) {
	store := &memoryKeyStore{
		activeID: activeKeyID,
		keys:     make(map[string]oidc.SigningKey, 1+len(extra)),
	}

	if err := store.addKey(activeKeyID, activePrivateKey); err != nil {
		return nil, err
	}
	for _, candidate := range extra {
		if err := store.addKey(candidate.keyID, candidate.privateKey); err != nil {
			return nil, err
		}
	}

	return store, nil
}

func (s *memoryKeyStore) addKey(keyID string, privateKey *rsa.PrivateKey) error {
	jwk, err := oidc.EncodeRSAPublicKeyJWK(keyID, &privateKey.PublicKey)
	if err != nil {
		return err
	}

	s.keys[keyID] = oidc.SigningKey{
		ID:         keyID,
		Algorithm:  "RS256",
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}
	s.jwks = append(s.jwks, jwk)

	return nil
}

func (s *memoryKeyStore) Active(_ context.Context) (oidc.SigningKey, error) {
	return s.keys[s.activeID], nil
}

func (s *memoryKeyStore) Get(_ context.Context, keyID string) (oidc.SigningKey, error) {
	key, ok := s.keys[keyID]
	if !ok {
		return oidc.SigningKey{}, errors.New("key not found")
	}
	return key, nil
}

func (s *memoryKeyStore) Public(_ context.Context) ([]oidc.JWK, error) {
	return append([]oidc.JWK(nil), s.jwks...), nil
}

type memoryClaimsResolver struct {
	items map[string]goauth.Account
}

func (r *memoryClaimsResolver) Resolve(_ context.Context, subjectID string) (goauth.Account, error) {
	return r.items[subjectID], nil
}

func codeChallengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func requireOAuthError(t *testing.T, err error, code string) {
	t.Helper()
	var oauthErr *oidc.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	require.Equal(t, code, oauthErr.Code)
}
