package goauth

import (
	"context"
	"time"
)

type MFAEnrollment struct {
	// RecoveryCodes are returned for pre-auth setup only, inactive until confirmation.
	RecoveryCodes []string
	ID            string
	Secret        string
	URL           string
	ExpiresAt     time.Time
}

// Auth must come from verified host authentication, never request JSON.
type MFAEnrollmentRequest struct {
	Auth        AuthContext
	Password    string
	CurrentCode string
	Binding     [32]byte
}
type MFAEnrollmentConfirmRequest struct {
	Auth         AuthContext
	Password     string
	EnrollmentID string
	Code         string
	Binding      [32]byte
}
type MFAChangeRequest struct {
	Auth     AuthContext
	Password string
	Code     string
}
type MFAEnrollmentRecord struct {
	SubjectID       SubjectID
	ID              string
	Revision        int64
	SecurityVersion int64
	SessionID       string
	Binding         [32]byte
	KeyID           string
	Ciphertext      []byte
	CreatedAt       time.Time
	ExpiresAt       time.Time
}
type MFAEnrollmentStore interface {
	EnsureMFAFactor(ctx context.Context, subject SubjectID) (MFAFactorRecord, error)
	SaveMFAEnrollment(ctx context.Context, enrollment MFAEnrollmentRecord) error
	LockMFAEnrollment(ctx context.Context, subject SubjectID) (MFAEnrollmentRecord, error)
	ReplaceMFAFactor(ctx context.Context, subject SubjectID, previous, next MFAFactorRecord) (bool, error)
	ReplaceMFARecovery(ctx context.Context, subject SubjectID, digests [][]byte) error
	CancelMFAEnrollment(ctx context.Context, subject SubjectID, sessionID string, binding [32]byte) error
	InvalidateMFAState(ctx context.Context, subject SubjectID) error
}
