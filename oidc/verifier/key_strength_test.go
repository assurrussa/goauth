//nolint:testpackage // Tests the remote JWKS verification flow using existing transport fixtures.
package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestRemoteJWKSRejectsWeakRSAKey(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Deliberately weak rejection fixture.
	require.NoError(t, err)
	now := time.Now().UTC()
	jwk := oidc.JWK{
		Kty: "RSA", Kid: "weak", Alg: "RS256", Use: "sig",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: "AQAB",
	}
	transport := &fakeOIDCTransport{t: t, issuer: testIssuer, jwksResponses: []oidc.JWKS{{Keys: []oidc.JWK{jwk}}}}
	service, err := New(Options{
		Issuer: testIssuer, Audience: reviewAudience,
		HTTPClient: &http.Client{Transport: transport}, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	token := signAccessToken(t, key, accessTokenInput{
		keyID: "weak", issuer: testIssuer, audience: reviewAudience,
		subject: "weak-key-subject", scopes: []string{oidc.ScopeOpenID}, expiresAt: now.Add(time.Minute), issuedAt: now,
	})
	_, err = service.VerifyAccessToken(t.Context(), token)
	require.Error(t, err)
	require.Empty(t, service.jwks)
	require.Equal(t, 1, transport.JWKSRequests())
}
