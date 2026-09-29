//nolint:testpackage,goconst,prealloc // Security test case clarity takes precedence over allocation optimization.
package verifier

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestAccessTokenProfiles(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	key := testRSAKey(t)
	for _, profile := range []AccessTokenProfile{"", AccessTokenProfileGoAuth, AccessTokenProfileZITADEL} {
		t.Run(string(profile), func(t *testing.T) {
			t.Parallel()
			svc, err := New(Options{
				Issuer: testIssuer, Audience: "shared-client", AccessTokenProfile: profile,
				Now: func() time.Time { return now }, HTTPClient: &http.Client{Transport: &fakeOIDCTransport{
					t: t, issuer: testIssuer,
					jwksResponses: []oidc.JWKS{{Keys: []oidc.JWK{testJWK(t, "key", &key.PublicKey)}}},
				}},
			})
			require.NoError(t, err)
			cases := []struct {
				name            string
				patch           jwt.MapClaims
				remove          string
				goauth, zitadel bool
			}{
				{name: "access", goauth: true, zitadel: true},
				{name: "ZITADEL access", remove: "token_use", zitadel: true},
				{name: "wrong token use", patch: jwt.MapClaims{"token_use": "id"}},
				{name: "token_use case variant", patch: jwt.MapClaims{"TOKEN_USE": "access"}, remove: "token_use", zitadel: true},
				{name: "case collision cannot hide wrong token_use", patch: jwt.MapClaims{"token_use": "id", "TOKEN_USE": "access"}},
				{name: "case variant cannot replace jti", patch: jwt.MapClaims{"JTI": "id"}, remove: "jti", goauth: true},
				{name: "nbf case collision", patch: jwt.MapClaims{"nbf": now.Add(time.Minute).Unix(), "NBF": now.Unix()}},
				{name: "empty token use", patch: jwt.MapClaims{"token_use": ""}},
				{name: "missing jti", remove: "jti", goauth: true},
				{name: "null jti", patch: jwt.MapClaims{"jti": nil}, goauth: true},
				{name: "numeric jti", patch: jwt.MapClaims{"jti": 17}},
				{name: "blank jti", patch: jwt.MapClaims{"jti": " "}, goauth: true},
				{name: "missing nbf", remove: "nbf", goauth: true},
				{name: "null nbf", patch: jwt.MapClaims{"nbf": nil}, goauth: true},
				{name: "string nbf", patch: jwt.MapClaims{"nbf": "100"}, goauth: true},
				{name: "future nbf", patch: jwt.MapClaims{"nbf": now.Add(time.Minute).Unix()}},
				{name: "expired", patch: jwt.MapClaims{"exp": now.Unix()}},
				{name: "future iat", patch: jwt.MapClaims{"iat": now.Add(time.Minute).Unix()}},
				{name: "wrong issuer", patch: jwt.MapClaims{"iss": testIssuer + "/"}},
				{name: "wrong audience", patch: jwt.MapClaims{"aud": "other"}},
			}
			for _, name := range []string{"nonce", "auth_time", "amr", "acr", "sid", "events", "at_hash", "c_hash", "s_hash"} {
				cases = append(cases, struct {
					name            string
					patch           jwt.MapClaims
					remove          string
					goauth, zitadel bool
				}{
					name: "ID/logout claim " + name, patch: jwt.MapClaims{name: nil}, goauth: true,
				})
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()
					claims := jwt.MapClaims{
						"iss": testIssuer, "aud": "shared-client", "sub": "subject", "exp": now.Add(time.Hour).Unix(),
						"iat": now.Unix(), "nbf": now.Unix(), "jti": "id", "token_use": "access",
					}
					delete(claims, tc.remove)
					for k, v := range tc.patch {
						claims[k] = v
					}
					_, err := svc.VerifyAccessToken(context.Background(), signToken(t, key, "key", claims))
					want := tc.goauth
					if profile == AccessTokenProfileZITADEL {
						want = tc.zitadel
					}
					if want {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
					}
				})
			}
		})
	}
	_, err := New(Options{Issuer: testIssuer, Audience: "shared-client", AccessTokenProfile: "automatic"})
	require.ErrorContains(t, err, "unsupported access token profile")
}
