package verifier

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/assurrussa/goauth/oidc"
)

// A provider may publish signing and encryption keys for several algorithms.
// Only keys compatible with our explicit RS256 profile participate in selection.
func verificationKeys(jwks oidc.JWKS) (map[string]*rsa.PublicKey, error) {
	keys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" || strings.TrimSpace(key.Kid) == "" ||
			(key.Use != "" && key.Use != "sig") || (key.Alg != "" && key.Alg != "RS256") {
			continue
		}
		publicKey, err := oidc.DecodeRSAPublicKeyJWK(key)
		if err != nil {
			return nil, fmt.Errorf("decode signing jwk %q: %w", key.Kid, err)
		}
		if previous, exists := keys[key.Kid]; exists && !previous.Equal(publicKey) {
			return nil, fmt.Errorf("ambiguous signing key id %q", key.Kid)
		}
		keys[key.Kid] = publicKey
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks contains no usable keys")
	}
	return keys, nil
}
