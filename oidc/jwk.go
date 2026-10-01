package oidc

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math"
	"math/big"
	"strings"
)

const jwkKeyTypeRSA = "RSA"

// ValidateRS256SigningJWKMetadata checks compatibility with the RS256 signing
// profile. Empty use/alg fields are allowed; kid is required. Call
// DecodeRSAPublicKeyJWK separately to validate the RSA key material.
func ValidateRS256SigningJWKMetadata(jwk JWK) error {
	if jwk.Kty != jwkKeyTypeRSA || strings.TrimSpace(jwk.Kid) == "" ||
		(jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != "RS256") {
		return errors.New("jwk metadata is incompatible with RS256 signing")
	}
	return nil
}

// ValidateRSAPublicKey checks the RSA signing key profile supported by OIDC.
func ValidateRSAPublicKey(key *rsa.PublicKey) error {
	if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) == 0 {
		return errors.New("invalid rsa modulus")
	}
	if key.N.BitLen() < 2048 {
		return errors.New("rsa modulus must be at least 2048 bits")
	}
	if key.E < 3 || key.E > math.MaxInt32 || key.E%2 == 0 {
		return errors.New("invalid rsa exponent")
	}
	return nil
}

func EncodeRSAPublicKeyJWK(keyID string, publicKey crypto.PublicKey) (JWK, error) {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok || rsaKey == nil {
		return JWK{}, errors.New("public key must be rsa")
	}
	if err := ValidateRSAPublicKey(rsaKey); err != nil {
		return JWK{}, err
	}

	return JWK{
		Kty: jwkKeyTypeRSA,
		Use: "sig",
		Kid: keyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}, nil
}

func DecodeRSAPublicKeyJWK(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != jwkKeyTypeRSA {
		return nil, errors.New("jwk is not rsa")
	}

	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	if len(modulusBytes) == 0 || len(exponentBytes) == 0 {
		return nil, errors.New("jwk modulus or exponent is empty")
	}

	exponent := new(big.Int).SetBytes(exponentBytes)
	if !exponent.IsInt64() || exponent.Int64() > math.MaxInt32 {
		return nil, errors.New("jwk exponent is too large")
	}

	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponent.Int64()),
	}
	if err := ValidateRSAPublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}
