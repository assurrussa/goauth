package oidc

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
)

func EncodeRSAPublicKeyJWK(keyID string, publicKey crypto.PublicKey) (JWK, error) {
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok || rsaKey == nil {
		return JWK{}, errors.New("public key must be rsa")
	}

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: keyID,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}, nil
}

func DecodeRSAPublicKeyJWK(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
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
	if !exponent.IsInt64() {
		return nil, errors.New("jwk exponent is too large")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponent.Int64()),
	}, nil
}
