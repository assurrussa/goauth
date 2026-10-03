package goauth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func compatibilityFixturePHC(profile Argon2idConfig, fill byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", profile.MemoryKiB, profile.Iterations, profile.Parallelism,
		base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, int(profile.SaltLength))),
		base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, int(profile.KeyLength))))
}

func compatibilityFixture(t *testing.T) (*boundedPasswordHasher, *legacyPasswordCompatibility) {
	t.Helper()
	delegate, err := NewArgon2idHasher(Argon2idConfig{})
	require.NoError(t, err)
	compat := &legacyPasswordCompatibility{
		currentProfile: delegate.config, currentDummyPHC: compatibilityFixturePHC(delegate.config, 1),
		legacyDummyPHC: compatibilityFixturePHC(legacyPasswordProfile(), 2),
	}
	hasher := &boundedPasswordHasher{
		delegate: delegate, active: make(chan struct{}, 1), dummyPHC: compat.currentDummyPHC, compatibility: compat,
	}
	return hasher, compat
}

func TestLegacyPasswordPolicyUsesSharedHashBudget(t *testing.T) {
	hasher, compat := compatibilityFixture(t)
	hasher.active <- struct{}{}
	require.ErrorIs(t, hasher.verifyCredential(compat.legacyDummyPHC, strings.Repeat("x", 129), PasswordInputPolicyLegacyBytes256),
		ErrPasswordHashOverloaded)
	require.ErrorIs(t, hasher.VerifyPassword(compat.currentDummyPHC, "standard"), ErrPasswordHashOverloaded)
	_, err := hasher.HashPassword("Standard-Passphrase-42")
	require.ErrorIs(t, err, ErrPasswordHashOverloaded)
	require.ErrorIs(t, hasher.verifyCredential(compat.legacyDummyPHC, "standard", "unknown"), ErrPasswordHashOverloaded)
}

func TestMixedPasswordProfilesExecuteSameDeterministicWork(t *testing.T) {
	hasher, compat := compatibilityFixture(t)
	current := compatibilityFixturePHC(compat.currentProfile, 3)
	legacy := compatibilityFixturePHC(legacyPasswordProfile(), 4)
	unsupportedProfile := compat.currentProfile
	unsupportedProfile.Iterations++
	unsupported := compatibilityFixturePHC(unsupportedProfile, 5)
	for _, record := range []struct {
		name, phc string
		policy    PasswordInputPolicy
	}{
		{"current strict", current, PasswordInputPolicyUnicode},
		{"legacy cost strict", legacy, PasswordInputPolicyUnicode},
		{"marked legacy", legacy, PasswordInputPolicyLegacyBytes256},
		{"missing", "", PasswordInputPolicyUnicode},
		{"malformed", "not-a-PHC", PasswordInputPolicyUnicode},
		{"unsupported cost", unsupported, PasswordInputPolicyUnicode},
		{"unknown policy", current, "unknown"},
		{"legacy marker wrong cost", current, PasswordInputPolicyLegacyBytes256},
	} {
		for _, input := range []struct{ name, value string }{
			{"normal mismatch", "Wrong-Passphrase-42"},
			{"129 code points", strings.Repeat("x", 129)},
			{"invalid UTF8", string([]byte{0xff, 0, 'x'})},
			{"256 bytes", strings.Repeat("y", 256)},
			{"128 four-byte runes", strings.Repeat("\U0001f600", 128)},
		} {
			t.Run(record.name+"/"+input.name, func(t *testing.T) {
				plan := compat.plan(record.phc, input.value, record.policy)
				require.True(t, matchesPasswordProfile(plan.work[0].phc, compat.currentProfile))
				require.True(t, matchesPasswordProfile(plan.work[1].phc, legacyPasswordProfile()))
				require.Equal(t, input.value, plan.work[0].password)
				require.Equal(t, input.value, plan.work[1].password)
				var calls []passwordVerificationWork
				err := hasher.verifyPlan(plan, func(phc, password string) error {
					require.Len(t, hasher.active, 1, "one slot must remain held across both sequential jobs")
					calls = append(calls, passwordVerificationWork{phc: phc, password: password})
					_, nestedErr := hasher.HashPassword("Nested-Work-Passphrase-42")
					require.ErrorIs(t, nestedErr, ErrPasswordHashOverloaded, "the second job cannot acquire an independent budget")
					return ErrInvalidCredentials
				})
				require.ErrorIs(t, err, ErrInvalidCredentials)
				require.Equal(t, plan.work[:], calls)
				require.Empty(t, hasher.active)
				// Invalid policy, input or PHC never selects a real credential.
				if record.name == "missing" || record.name == "malformed" || record.name == "unsupported cost" ||
					record.name == "unknown policy" || record.name == "legacy marker wrong cost" ||
					(record.policy == PasswordInputPolicyUnicode && !validPasswordInput(input.value)) ||
					(record.policy == PasswordInputPolicyLegacyBytes256 && len(input.value) > 256) {
					require.Equal(t, -1, plan.selected)
					require.Equal(t, compat.currentDummyPHC, plan.work[0].phc)
					require.Equal(t, compat.legacyDummyPHC, plan.work[1].phc)
					// Even two accidental dummy matches cannot authenticate a denied record.
					calls = nil
					err = hasher.verifyPlan(plan, func(phc, password string) error {
						calls = append(calls, passwordVerificationWork{phc, password})
						return nil
					})
					require.ErrorIs(t, err, ErrInvalidCredentials)
					require.Len(t, calls, 2)
				}
			})
		}
	}
}

func TestMixedPasswordWorkRespectsConfiguredCurrentProfile(t *testing.T) {
	for _, profile := range []Argon2idConfig{
		{MemoryKiB: 32768, Iterations: 2, Parallelism: 2, SaltLength: 32, KeyLength: 48},
		legacyPasswordProfile(),
	} {
		compat := &legacyPasswordCompatibility{
			currentProfile:  profile,
			currentDummyPHC: compatibilityFixturePHC(profile, 1), legacyDummyPHC: compatibilityFixturePHC(legacyPasswordProfile(), 2),
		}
		phc := compatibilityFixturePHC(profile, 3)
		plan := compat.plan(phc, "Normal-Passphrase-42", PasswordInputPolicyUnicode)
		require.Equal(t, 0, plan.selected)
		require.Equal(t, phc, plan.work[0].phc)
		require.True(t, matchesPasswordProfile(plan.work[0].phc, profile))
		require.True(t, matchesPasswordProfile(plan.work[1].phc, legacyPasswordProfile()))
	}
}
