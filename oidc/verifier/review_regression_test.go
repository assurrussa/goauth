//nolint:testpackage // Exercises cache coordination and JWKS selection internals.
package verifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestReviewJWKSFiltersIncompatibleKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signing, err := oidc.EncodeRSAPublicKeyJWK("signing", &key.PublicKey)
	require.NoError(t, err)
	encryption := signing
	encryption.Kid, encryption.Use = "encryption", "enc"
	otherAlgorithm := signing
	otherAlgorithm.Kid, otherAlgorithm.Alg = "pss", "PS256"
	keys, err := verificationKeys(oidc.JWKS{Keys: []oidc.JWK{
		{Kty: "EC", Kid: "elliptic", Use: "sig", Alg: "ES256"},
		encryption, otherAlgorithm, signing,
	}})
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.True(t, keys["signing"].Equal(&key.PublicKey))
	_, err = verificationKeys(oidc.JWKS{Keys: []oidc.JWK{encryption, otherAlgorithm}})
	require.Error(t, err)

	conflict := signing
	conflict.N = "AQAB"
	_, err = verificationKeys(oidc.JWKS{Keys: []oidc.JWK{signing, conflict}})
	require.ErrorContains(t, err, "ambiguous")
	_, err = verificationKeys(oidc.JWKS{Keys: []oidc.JWK{signing, signing}})
	require.NoError(t, err)
}

func TestReviewDiscoveryFailuresAreBackedOff(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	now := time.Now().UTC()
	service, err := New(Options{
		Issuer: server.URL, Audience: "review", AllowInsecureHTTP: true,
		Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	for range 10 {
		require.Error(t, service.ensureJWKS(t.Context(), false))
	}
	require.EqualValues(t, 1, requests.Load())
	service.mu.Lock()
	service.refreshRetryAt = now.Add(-time.Second)
	service.mu.Unlock()
	require.Error(t, service.ensureJWKS(t.Context(), false))
	require.EqualValues(t, 2, requests.Load())
}

func TestReviewVerifiedAudienceIsTheMatchedAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now().UTC()
	service, err := New(Options{Issuer: "https://review.example.test", Audience: "our-api", Now: func() time.Time { return now }})
	require.NoError(t, err)
	service.jwks = map[string]*rsa.PublicKey{"review": &key.PublicKey}
	service.jwksFetched = now
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://review.example.test", "sub": "review-subject", "aud": []string{"other-api", "our-api"},
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "token_use": "access",
	})
	token.Header["kid"] = "review"
	raw, err := token.SignedString(key)
	require.NoError(t, err)
	verified, err := service.VerifyAccessToken(context.Background(), raw)
	require.NoError(t, err)
	require.Equal(t, "our-api", verified.Audience)
}
