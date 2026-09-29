package goauth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestPartialPasswordPolicyKeepsBlocklist(t *testing.T) {
	t.Parallel()
	require.ErrorIs(t, (goauth.PasswordPolicy{MinLength: 8}).Validate("password123"), goauth.ErrCommonPassword)
	require.ErrorIs(t, (goauth.PasswordPolicy{MaxLength: 64}).Validate("password123"), goauth.ErrCommonPassword)
	require.NoError(t, (goauth.PasswordPolicy{DisableBlocklist: true}).Validate("password123"))
	require.ErrorIs(t, (goauth.PasswordPolicy{DisableBlocklist: true}).Validate("short"), goauth.ErrInvalidPassword)
}
