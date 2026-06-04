//nolint:testpackage,depguard // Tests verify internal error behavior and JWT validation paths.
package verifier

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const testIssuer = "https://issuer.example"

func TestVerifyAccessTokenCachesJWKSAndContextHelpers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	issuer := testIssuer
	key := testRSAKey(t)
	jwk := testJWK(t, "kid-1", &key.PublicKey)
	transport := &fakeOIDCTransport{
		t:             t,
		issuer:        issuer,
		jwksResponses: []oidc.JWKS{{Keys: []oidc.JWK{jwk}}},
	}

	verifier, err := New(Options{
		Issuer:         issuer,
		Audience:       "pet-app",
		RequiredScopes: []string{oidc.ScopeEmail},
		HTTPClient:     &http.Client{Transport: transport},
		Now:            func() time.Time { return now },
	})
	require.NoError(t, err)

	token := signAccessToken(t, key, accessTokenInput{
		keyID:     "kid-1",
		issuer:    issuer,
		audience:  "pet-app",
		subject:   "subject-1",
		scopes:    []string{oidc.ScopeOpenID, oidc.ScopeEmail},
		expiresAt: now.Add(15 * time.Minute),
		issuedAt:  now,
	})

	verified, err := verifier.VerifyAccessToken(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "subject-1", verified.Subject)
	require.Equal(t, issuer, verified.Issuer)
	require.Equal(t, "pet-app", verified.Audience)
	require.Equal(t, "pet-app", verified.ClientID)
	require.Equal(t, []string{oidc.ScopeEmail, oidc.ScopeOpenID}, verified.Scopes)
	require.Equal(t, "kid-1", verified.KeyID)

	ctx := WithVerifiedAccessToken(context.Background(), verified)
	fromCtx, ok := VerifiedAccessTokenFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, verified, fromCtx)
	require.Equal(t, token, ExtractBearerToken("Bearer "+token))

	_, err = verifier.VerifyAccessToken(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, 1, transport.JWKSRequests())
}

func TestVerifyAccessTokenRefreshesJWKSOnUnknownKeyID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	issuer := testIssuer
	oldKey := testRSAKey(t)
	newKey := testRSAKey(t)
	oldJWK := testJWK(t, "kid-old", &oldKey.PublicKey)
	newJWK := testJWK(t, "kid-new", &newKey.PublicKey)

	transport := &fakeOIDCTransport{
		t:      t,
		issuer: issuer,
		jwksResponses: []oidc.JWKS{
			{Keys: []oidc.JWK{oldJWK}},
			{Keys: []oidc.JWK{oldJWK, newJWK}},
		},
	}

	verifier, err := New(Options{
		Issuer:     issuer,
		Audience:   "pet-app",
		HTTPClient: &http.Client{Transport: transport},
		Now:        func() time.Time { return now },
	})
	require.NoError(t, err)

	token := signAccessToken(t, newKey, accessTokenInput{
		keyID:     "kid-new",
		issuer:    issuer,
		audience:  "pet-app",
		subject:   "subject-2",
		scopes:    []string{oidc.ScopeOpenID},
		expiresAt: now.Add(15 * time.Minute),
		issuedAt:  now,
	})

	verified, err := verifier.VerifyAccessToken(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "kid-new", verified.KeyID)
	require.Equal(t, 2, transport.JWKSRequests())
}

func TestVerifyAccessTokenRejectsInvalidTokens(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	issuer := testIssuer
	key := testRSAKey(t)
	jwk := testJWK(t, "kid-1", &key.PublicKey)

	tests := []struct {
		name          string
		requiredScope []string
		token         string
		wantErr       string
	}{
		{
			name:          "missing required scope",
			requiredScope: []string{oidc.ScopeEmail},
			token: signAccessToken(t, key, accessTokenInput{
				keyID:     "kid-1",
				issuer:    issuer,
				audience:  "pet-app",
				subject:   "subject-1",
				scopes:    []string{oidc.ScopeOpenID},
				expiresAt: now.Add(15 * time.Minute),
				issuedAt:  now,
			}),
			wantErr: `required scope "email" is missing`,
		},
		{
			name: "wrong token use",
			token: signToken(t, key, "kid-1", jwt.MapClaims{
				"iss":       issuer,
				"sub":       "subject-1",
				"aud":       []string{"pet-app"},
				"exp":       now.Add(15 * time.Minute).Unix(),
				"iat":       now.Unix(),
				"nbf":       now.Unix(),
				"scope":     oidc.ScopeOpenID,
				"client_id": "pet-app",
				"token_use": "id",
			}),
			wantErr: "token_use must be access",
		},
		{
			name: "missing token use is accepted",
			token: signToken(t, key, "kid-1", jwt.MapClaims{
				"iss":       issuer,
				"sub":       "subject-1",
				"aud":       []string{"pet-app"},
				"exp":       now.Add(15 * time.Minute).Unix(),
				"iat":       now.Unix(),
				"nbf":       now.Unix(),
				"scope":     oidc.ScopeOpenID,
				"client_id": "pet-app",
			}),
		},
		{
			name: "wrong audience",
			token: signAccessToken(t, key, accessTokenInput{
				keyID:     "kid-1",
				issuer:    issuer,
				audience:  "another-audience",
				subject:   "subject-1",
				scopes:    []string{oidc.ScopeOpenID},
				expiresAt: now.Add(15 * time.Minute),
				issuedAt:  now,
			}),
			wantErr: "token has invalid audience",
		},
		{
			name: "expired token",
			token: signAccessToken(t, key, accessTokenInput{
				keyID:     "kid-1",
				issuer:    issuer,
				audience:  "pet-app",
				subject:   "subject-1",
				scopes:    []string{oidc.ScopeOpenID},
				expiresAt: now.Add(-time.Minute),
				issuedAt:  now.Add(-2 * time.Minute),
			}),
			wantErr: "token is expired",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport := &fakeOIDCTransport{
				t:             t,
				issuer:        issuer,
				jwksResponses: []oidc.JWKS{{Keys: []oidc.JWK{jwk}}},
			}
			verifier, err := New(Options{
				Issuer:         issuer,
				Audience:       "pet-app",
				RequiredScopes: tt.requiredScope,
				HTTPClient:     &http.Client{Transport: transport},
				Now:            func() time.Time { return now },
			})
			require.NoError(t, err)

			_, err = verifier.VerifyAccessToken(context.Background(), tt.token)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestVerifiedAccessTokenFromContextEmpty(t *testing.T) {
	t.Parallel()

	_, ok := VerifiedAccessTokenFromContext(context.Background())
	require.False(t, ok)
	require.Empty(t, ExtractBearerToken("Basic token"))
}

func TestVerifyAccessTokenReportsUnknownKeyAfterRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	issuer := testIssuer
	key := testRSAKey(t)
	jwk := testJWK(t, "kid-1", &key.PublicKey)

	transport := &fakeOIDCTransport{
		t:             t,
		issuer:        issuer,
		jwksResponses: []oidc.JWKS{{Keys: []oidc.JWK{jwk}}},
	}

	verifier, err := New(Options{
		Issuer:     issuer,
		Audience:   "pet-app",
		HTTPClient: &http.Client{Transport: transport},
		Now:        func() time.Time { return now },
	})
	require.NoError(t, err)

	otherKey := testRSAKey(t)
	token := signAccessToken(t, otherKey, accessTokenInput{
		keyID:     "kid-2",
		issuer:    issuer,
		audience:  "pet-app",
		subject:   "subject-1",
		scopes:    []string{oidc.ScopeOpenID},
		expiresAt: now.Add(15 * time.Minute),
		issuedAt:  now,
	})

	_, err = verifier.VerifyAccessToken(context.Background(), token)
	require.Error(t, err)
	require.ErrorIs(t, err, errUnknownKeyID)
}

type fakeOIDCTransport struct {
	t             *testing.T
	issuer        string
	jwksResponses []oidc.JWKS

	mu           sync.Mutex
	jwksRequests int
}

func (t *fakeOIDCTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.String() {
	case t.issuer + "/.well-known/openid-configuration":
		return jsonResponse(oidc.DiscoveryMetadata{
			Issuer:                            t.issuer,
			JWKSURI:                           t.issuer + "/oauth2/jwks",
			TokenEndpointAuthMethodsSupported: []string{oidc.TokenEndpointAuthMethodNone},
		}), nil
	case t.issuer + "/oauth2/jwks":
		t.mu.Lock()
		t.jwksRequests++
		callNo := t.jwksRequests
		t.mu.Unlock()

		if len(t.jwksResponses) == 0 {
			return jsonResponse(oidc.JWKS{}), nil
		}

		index := callNo - 1
		if index >= len(t.jwksResponses) {
			index = len(t.jwksResponses) - 1
		}

		return jsonResponse(t.jwksResponses[index]), nil
	default:
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(nil)),
			Request:    req,
		}, nil
	}
}

func (t *fakeOIDCTransport) JWKSRequests() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.jwksRequests
}

func jsonResponse(value any) *http.Response {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

type accessTokenInput struct {
	keyID     string
	issuer    string
	audience  string
	subject   string
	scopes    []string
	expiresAt time.Time
	issuedAt  time.Time
}

func signAccessToken(t *testing.T, key *rsa.PrivateKey, input accessTokenInput) string {
	t.Helper()

	return signToken(t, key, input.keyID, jwt.MapClaims{
		"iss":       input.issuer,
		"sub":       input.subject,
		"aud":       []string{input.audience},
		"exp":       input.expiresAt.Unix(),
		"iat":       input.issuedAt.Unix(),
		"nbf":       input.issuedAt.Unix(),
		"scope":     oidc.ScopeString(input.scopes),
		"client_id": input.audience,
		"token_use": "access",
	})
}

func signToken(t *testing.T, key *rsa.PrivateKey, keyID string, claims jwt.Claims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signed, err := token.SignedString(key)
	require.NoError(t, err)

	return signed
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return key
}

func testJWK(t *testing.T, keyID string, publicKey *rsa.PublicKey) oidc.JWK {
	t.Helper()

	jwk, err := oidc.EncodeRSAPublicKeyJWK(keyID, publicKey)
	require.NoError(t, err)

	return jwk
}
