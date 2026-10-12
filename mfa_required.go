package goauth

import (
	"context"
	"errors"
)

// MFAMode is trusted runtime configuration, never a browser-supplied login option.
type MFAMode string

const (
	MFAModeOptional MFAMode = "optional"
	MFAModeRequired MFAMode = "required"
)

type MFALoginKind string

const (
	MFALoginKindFactor     MFALoginKind = "factor"
	MFALoginKindEnrollment MFALoginKind = "enrollment"
)

// MFALoginSetup is encrypted setup material bound to one password-verified
// continuation. It has no lifetime independent of its parent pending record.
type MFALoginSetup struct {
	ID              string
	KeyID           string
	Ciphertext      []byte
	RecoveryDigests [][]byte
}

// MFASessionAdmission is immutable server-written provenance. External admission
// is only written by LoginExternal after the host has verified that authority.
type MFASessionAdmission string

const (
	MFASessionAdmissionFactor   MFASessionAdmission = "factor"
	MFASessionAdmissionExternal MFASessionAdmission = "external"
)

// MFARequiredStore extends the optional module without silently upgrading
// third-party stores that cannot enforce required enrollment and live admission.
type MFARequiredStore interface {
	MFAStore
	SaveMFALoginSetup(ctx context.Context, pending MFALoginPending, setup MFALoginSetup) error
	MarkMFASessionAdmission(ctx context.Context, session Session, admission MFASessionAdmission) error
	AdmitRequiredMFASession(ctx context.Context, session Session) error
}

func validateMFAMode(config Config) error {
	switch config.MFAMode {
	case "", MFAModeOptional:
		return nil
	case MFAModeRequired:
		if config.MFAKeys == nil {
			return ErrMFAUnavailable
		}
		if _, ok := config.Store.(MFARequiredStore); !ok {
			return errors.New("required MFA needs enrollment and session admission storage")
		}
		return nil
	default:
		return errors.New("invalid MFA mode")
	}
}

func (r *Runtime) markMFASessionAdmission(
	ctx context.Context, session Session, admission MFASessionAdmission,
) error {
	if admission == "" {
		return nil
	}
	store, ok := r.mfaStore.(MFARequiredStore)
	if !ok {
		if r.mfaMode == MFAModeRequired {
			return ErrMFAUnavailable
		}
		return nil
	}
	return store.MarkMFASessionAdmission(ctx, session, admission)
}

func (r *Runtime) admitRequiredMFASession(ctx context.Context, session Session) error {
	if r.mfaMode != MFAModeRequired || session.Scope != SessionScopeAuthenticated {
		return nil
	}
	store, ok := r.mfaStore.(MFARequiredStore)
	if !ok {
		return ErrMFAUnavailable
	}
	return store.AdmitRequiredMFASession(ctx, session)
}

// MFAMode returns the normalized trusted admission policy.
func (r *Runtime) MFAMode() MFAMode {
	if r.mfaMode == MFAModeRequired {
		return MFAModeRequired
	}
	return MFAModeOptional
}
