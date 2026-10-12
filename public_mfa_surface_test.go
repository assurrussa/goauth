package goauth_test

import (
	"context"
	"testing"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func TestPublicLocalMFASurfaceCompiles(t *testing.T) {
	t.Helper()
	var _ goauth.MFAStore = (*postgres.Store)(nil)
	type signature1 func(*goauth.Runtime, context.Context, goauth.LoginRequest, [32]byte) (goauth.LocalLoginResult, error)
	var _ signature1 = (*goauth.Runtime).BeginLocalLogin
	type signature2 func(*goauth.Runtime, context.Context, string, [32]byte, string) (goauth.LoginResult, error)
	var _ signature2 = (*goauth.Runtime).CompleteLocalLogin
	type signature3 func(*goauth.Runtime, context.Context, goauth.MFAEnrollmentRequest) (goauth.MFAEnrollment, error)
	var _ signature3 = (*goauth.Runtime).BeginMFAEnrollment
	type signature4 func(*goauth.Runtime, context.Context, goauth.MFAEnrollmentConfirmRequest) ([]string, error)
	var _ signature4 = (*goauth.Runtime).ConfirmMFAEnrollment
	type signature5 func(*goauth.Runtime, context.Context, goauth.MFAChangeRequest) error
	var _ signature5 = (*goauth.Runtime).DisableMFA
	type signature6 func(*goauth.Runtime, context.Context, goauth.MFAChangeRequest) ([]string, error)
	var _ signature6 = (*goauth.Runtime).RegenerateMFARecovery
	_ = goauth.Config{MFAKeys: &goauth.KeyRing{}}
	_ = goauth.MFAFactorCodec{}
	_ = goauth.ErrMFARequired
	_ = goauth.ErrMFAUnavailable
	_ = goauth.ErrMFALoginDenied
}
