package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const (
	encodedRSAExponent = "AQAB"
	rsaJWKType         = "RSA"
)

func TestRSAJWKRejectsWeakAndMalformedKeys(t *testing.T) {
	t.Parallel()
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	weak, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Deliberately weak rejection fixture.
	require.NoError(t, err)
	for _, key := range []*rsa.PublicKey{
		nil,
		{},
		{N: big.NewInt(0), E: 65537},
		{N: big.NewInt(-1), E: 65537},
		&weak.PublicKey,
		{N: strong.N, E: 0},
		{N: strong.N, E: 2},
		{N: strong.N, E: -3},
	} {
		require.Error(t, oidc.ValidateRSAPublicKey(key))
		_, err := oidc.EncodeRSAPublicKeyJWK("key", key)
		require.Error(t, err)
	}
	for _, bits := range []int{2048, 3072} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)
		jwk, err := oidc.EncodeRSAPublicKeyJWK("key", &key.PublicKey)
		require.NoError(t, err)
		decoded, err := oidc.DecodeRSAPublicKeyJWK(jwk)
		require.NoError(t, err)
		require.True(t, key.PublicKey.Equal(decoded))
	}
	encodedModulus := base64.RawURLEncoding.EncodeToString(strong.N.Bytes())
	for _, jwk := range []oidc.JWK{
		{Kty: rsaJWKType, N: base64.RawURLEncoding.EncodeToString(weak.N.Bytes()), E: encodedRSAExponent},
		{Kty: rsaJWKType, N: "", E: encodedRSAExponent},
		{Kty: rsaJWKType, N: "AA", E: encodedRSAExponent},
		{Kty: rsaJWKType, N: encodedModulus, E: ""},
		{Kty: rsaJWKType, N: encodedModulus, E: "AA"},
		{Kty: rsaJWKType, N: encodedModulus, E: "Ag"},
		{Kty: rsaJWKType, N: encodedModulus, E: "gAAAAA"},       // Exceeds signed 32-bit int.
		{Kty: rsaJWKType, N: encodedModulus, E: "AQAAAAAAAAAA"}, // Exceeds signed 64-bit int.
	} {
		_, err := oidc.DecodeRSAPublicKeyJWK(jwk)
		require.Error(t, err)
	}
}

func TestNilClientSecretVerifierFuncFailsClosed(t *testing.T) {
	t.Parallel()
	var verify oidc.ClientSecretVerifierFunc
	require.Error(t, verify.VerifyClientSecret(context.Background(), "client", "secret"))
}

func TestRSAJWKEncoderRejectsBlankSigningKeyID(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, id := range []string{"", " \t\n"} {
		jwk, err := oidc.EncodeRSAPublicKeyJWK(id, &key.PublicKey)
		require.Error(t, err)
		require.Empty(t, jwk)
	}
	jwk, err := oidc.EncodeRSAPublicKeyJWK("key", &key.PublicKey)
	require.NoError(t, err)
	require.NoError(t, oidc.ValidateRS256SigningJWKMetadata(jwk))
}
