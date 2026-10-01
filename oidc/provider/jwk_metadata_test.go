//nolint:testpackage // Uses a custom signing-key store to exercise provider JWKS publication.
package provider

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestProviderJWKSRejectsIncompatibleSigningMetadata(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*oidc.JWK)
		valid  bool
	}{
		{name: "RS256 signing", valid: true},
		{name: "optional use and algorithm", mutate: func(k *oidc.JWK) { k.Use, k.Alg = "", "" }, valid: true},
		{name: "empty key id", mutate: func(k *oidc.JWK) { k.Kid = "" }},
		{name: "blank key id", mutate: func(k *oidc.JWK) { k.Kid = " \t" }},
		{name: "encryption key", mutate: func(k *oidc.JWK) { k.Use = "enc" }},
		{name: "other algorithm", mutate: func(k *oidc.JWK) { k.Alg = "RS512" }},
		{name: "other key type", mutate: func(k *oidc.JWK) { k.Kty = "EC" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newOIDCTestHarness(t)
			if tc.mutate != nil {
				tc.mutate(&h.keys.jwks[0])
			}
			keys, err := h.service.JWKS(t.Context())
			if tc.valid {
				require.NoError(t, err)
				require.Len(t, keys.Keys, 1)
			} else {
				require.Error(t, err)
				require.Empty(t, keys.Keys)
			}
		})
	}
}
