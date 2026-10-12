package goauth_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/testkit"
)

func TestRequiredMFAConfigurationFailsClosed(t *testing.T) {
	for _, mode := range []goauth.MFAMode{"", goauth.MFAModeOptional} {
		fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.MFAMode = mode })
		require.NoError(t, err)
		require.Equal(t, goauth.MFAModeOptional, fixture.Runtime.MFAMode())
	}
	_, err := testkit.NewRuntime(func(c *goauth.Config) { c.MFAMode = goauth.MFAModeRequired })
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	_, err = testkit.NewRuntime(func(c *goauth.Config) { c.MFAMode = "browser-selected" })
	require.Error(t, err)
	keys, err := goauth.NewKeyRing("required", goauth.Key{ID: "required", Material: bytes.Repeat([]byte{87}, 32)})
	require.NoError(t, err)
	_, err = testkit.NewRuntime(func(c *goauth.Config) { c.MFAMode = goauth.MFAModeRequired; c.MFAKeys = &keys })
	require.ErrorContains(t, err, "required MFA needs")
}

func TestPublicRequiredMFASurfaceCompiles(t *testing.T) {
	t.Helper()
	var _ goauth.MFARequiredStore = (*postgres.Store)(nil)
	type modeSignature func(*goauth.Runtime) goauth.MFAMode
	type beginEnrollmentSignature func(
		*goauth.Runtime, context.Context, string, [32]byte,
	) (goauth.MFAEnrollment, error)
	type completeEnrollmentSignature func(
		*goauth.Runtime, context.Context, string, string, [32]byte, string,
	) (goauth.LoginResult, error)
	var _ modeSignature = (*goauth.Runtime).MFAMode
	var _ beginEnrollmentSignature = (*goauth.Runtime).BeginLocalLoginEnrollment
	var _ completeEnrollmentSignature = (*goauth.Runtime).CompleteLocalLoginEnrollment
	_ = goauth.MFALoginChallenge{Kind: goauth.MFALoginKindEnrollment}
	_ = goauth.MFAEnrollment{RecoveryCodes: []string{}}
}
