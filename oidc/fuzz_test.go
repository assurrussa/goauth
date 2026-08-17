package oidc_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/assurrussa/goauth/oidc"
)

func FuzzOIDCScopeInput(f *testing.F) {
	f.Add("openid profile email")
	f.Add("  offline_access\topenid openid\napi:read ")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		scopes := oidc.ParseScope(input)
		roundTrip := oidc.ParseScope(oidc.ScopeString(scopes))
		if !slices.Equal(scopes, roundTrip) {
			t.Fatalf("scope normalization is not idempotent: %q -> %q -> %q", input, scopes, roundTrip)
		}
		for index, scope := range scopes {
			if strings.TrimSpace(scope) == "" {
				t.Fatal("normalized scope contains an empty entry")
			}
			if index > 0 && scopes[index-1] >= scope {
				t.Fatalf("normalized scopes are not strictly ordered: %q", scopes)
			}
		}
	})
}

func FuzzOIDCJWKInput(f *testing.F) {
	f.Add("RSA", "AQAB", "AQAB")
	f.Add("EC", "", "")
	f.Add("RSA", "%%%", "AQAB")

	f.Fuzz(func(t *testing.T, keyType, modulus, exponent string) {
		key, err := oidc.DecodeRSAPublicKeyJWK(oidc.JWK{
			Kty: keyType,
			N:   modulus,
			E:   exponent,
		})
		if err == nil && (key == nil || key.N == nil || key.N.Sign() <= 0 || key.E <= 0) {
			t.Fatalf("decoder accepted an unusable RSA key: %#v", key)
		}
	})
}
