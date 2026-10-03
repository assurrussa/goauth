package testkit_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const trustedSetInvalidField = "invalid request"

func TestTrustedLocalPasswordStoreGuards(t *testing.T) {
	f, err := testkit.NewRuntime()
	require.NoError(t, err)
	//nolint:gosec // Synthetic fixture password, never an external account.
	account, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "set-store@example.test", Password: "Set-Store-Fixture-Passphrase-42",
	})
	require.NoError(t, err)
	before, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	base := goauth.TrustedLocalPasswordStoreRequest{
		SubjectID:           account.Subject.ID,
		ExpectedPasswordPHC: before.PasswordPHC, ExpectedPasswordInputPolicy: before.PasswordInputPolicy,
		ExpectedSecurityVersion: account.Subject.SecurityVersion, NewPasswordPHC: before.PasswordPHC, Now: time.Now().UTC(),
	}
	for _, field := range []string{"version", "phc", "policy", "missing", trustedSetInvalidField} {
		stale := base
		expected := goauth.ErrPasswordChangeConflict
		switch field {
		case "version":
			stale.ExpectedSecurityVersion++
			expected = goauth.ErrSecurityVersionMismatch
		case "phc":
			stale.ExpectedPasswordPHC += "stale"
		case "policy":
			stale.ExpectedPasswordInputPolicy = goauth.PasswordInputPolicyLegacyBytes256
		case "missing":
			stale.SubjectID = goauth.NewSubjectID()
			expected = goauth.ErrAccountNotFound
		case trustedSetInvalidField:
			stale.Now = time.Time{}
		}
		changed, err := f.Store.SetTrustedLocalPassword(t.Context(), stale)
		if field == trustedSetInvalidField {
			require.Error(t, err)
		} else {
			require.ErrorIs(t, err, expected)
		}
		require.Zero(t, changed)
		after, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
		require.NoError(t, err)
		require.Equal(t, before, after)
	}
}
