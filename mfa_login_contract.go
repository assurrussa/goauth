package goauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

var (
	ErrMFARequired    = errors.New("second factor required")
	ErrMFALoginDenied = errors.New("MFA login denied")
)

const MFALoginLifetime = 3 * time.Minute

// MFALocalAdmissionStore must remain enabled even when MFA keys are absent.
// A legacy custom store may omit it only if it cannot contain enrolled factors.
type MFALocalAdmissionStore interface {
	LocalMFARequired(ctx context.Context, subject SubjectID) (bool, error)
}

// MFALoginPending is server-side continuation state, not authorization.
// ID is a random selector. BindingDigest hashes independent server browser state.
type MFALoginPending struct {
	Kind            MFALoginKind
	Setup           MFALoginSetup
	ID              string
	SubjectID       SubjectID
	Realm           Realm
	SecurityVersion int64
	FactorID        string
	FactorRevision  int64
	BindingDigest   [32]byte
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}

// MFAStore operations join the caller's transaction with subject, factor, then
// pending locks. Consumption is exact-record CAS, never a read followed by delete.
type MFAStore interface {
	MFAFactorStore
	MFALocalAdmissionStore
	MFAEnrollmentStore
	FindMFALoginSubject(ctx context.Context, id string) (SubjectID, error)
	CreateMFALogin(ctx context.Context, pending MFALoginPending) error
	LockMFALogin(ctx context.Context, id string) (MFALoginPending, error)
	ConsumeMFALogin(ctx context.Context, pending MFALoginPending) (bool, error)
}

func NewMFALoginID() (string, error) {
	raw := make([]byte, 32)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validMFALoginID(id string) bool {
	if len(id) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(id)
	defer clear(raw)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == id
}

// ValidateMFALoginPending validates a locked snapshot; it does not consume it.
// Sample now after waiting for locks, then independently check realm membership.
func ValidateMFALoginPending(pending MFALoginPending, account Account, factor MFAFactorRecord, realm Realm,
	binding [32]byte, now time.Time,
) error {
	return validateMFALoginPurpose(pending, account, factor, realm, binding, now, MFALoginKindFactor)
}

func normalizedMFALoginKind(kind MFALoginKind) MFALoginKind {
	if kind == "" {
		return MFALoginKindFactor
	}
	return kind
}

func validateMFALoginPurpose(pending MFALoginPending, account Account, factor MFAFactorRecord,
	realm Realm, binding [32]byte, now time.Time, kind MFALoginKind,
) error {
	var empty [32]byte
	if normalizedMFALoginKind(pending.Kind) != kind ||
		(kind != MFALoginKindFactor && kind != MFALoginKindEnrollment) ||
		!validMFALoginID(pending.ID) || pending.SubjectID.IsZero() ||
		pending.SubjectID != account.Subject.ID || account.Subject.Status != SubjectStatusActive ||
		pending.SecurityVersion < 1 || pending.SecurityVersion != account.Subject.SecurityVersion ||
		realm.Validate() != nil || pending.Realm != realm ||
		factor.Enabled != (kind == MFALoginKindFactor) || pending.FactorID != factor.ID ||
		pending.FactorRevision < 1 || pending.FactorRevision != factor.Revision ||
		binding == empty || subtle.ConstantTimeCompare(pending.BindingDigest[:], binding[:]) != 1 ||
		pending.AuthenticatedAt.IsZero() || pending.AuthenticatedAt.After(now) ||
		!pending.ExpiresAt.After(pending.AuthenticatedAt) ||
		pending.ExpiresAt.Sub(pending.AuthenticatedAt) > MFALoginLifetime ||
		!now.Before(pending.ExpiresAt) {
		return ErrMFALoginDenied
	}
	return nil
}
