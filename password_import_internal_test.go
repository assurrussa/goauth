package goauth

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLegacyPasswordPolicyUsesSharedHashBudget(t *testing.T) {
	delegate, err := NewArgon2idHasher(Argon2idConfig{})
	require.NoError(t, err)
	hasher := &boundedPasswordHasher{delegate: delegate, active: make(chan struct{}, 1)}
	phc := "$argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" +
		base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	hasher.active <- struct{}{}
	require.ErrorIs(t,
		hasher.verifyCredential(phc, strings.Repeat("x", 129), PasswordInputPolicyLegacyBytes256), ErrPasswordHashOverloaded)
	require.ErrorIs(t, hasher.VerifyPassword(phc, "standard"), ErrPasswordHashOverloaded)
	_, err = hasher.HashPassword("Standard-Passphrase-42")
	require.ErrorIs(t, err, ErrPasswordHashOverloaded)
	require.ErrorIs(t, hasher.verifyCredential(phc, "standard", "unknown"), ErrInvalidCredentials)
}
