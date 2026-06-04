package core

import (
	"context"
	"errors"
	"time"
)

//go:generate toolsmocks

var ErrSessionNotFound = errors.New("session not found")

// SubjectReader resolves canonical subjects from identity input.
type SubjectReader interface {
	GetByEmail(ctx context.Context, email string) (Subject, error)
}

// SubjectLookup resolves canonical subjects by their stable canonical identifier.
type SubjectLookup interface {
	GetByID(ctx context.Context, subjectID SubjectID) (Subject, error)
}

// SubjectWriter persists canonical subject mutations.
type SubjectWriter interface {
	CreateUser(ctx context.Context, subject Subject) (Subject, error)
	UpdatePassword(ctx context.Context, subject Subject, passwordHash string) error
}

type SubjectProfileWriter interface {
	UpdateProfile(ctx context.Context, subjectID SubjectID, patch SubjectProfilePatch) error
}

// SubjectCredentials resolves secrets for an already loaded subject.
type SubjectCredentials interface {
	GetPasswordHash(ctx context.Context, subject Subject) (string, error)
}

// RefreshTokenStore reserves the neutral refresh-token boundary for progressive migration.
type RefreshTokenStore interface {
	Save(ctx context.Context, session AuthSession) error
	Get(ctx context.Context, token string) (AuthSession, error)
	GetBySessionID(ctx context.Context, sessionID int64) (AuthSession, error)
	ListBySubject(ctx context.Context, subjectID SubjectID) ([]AuthSession, error)
	Delete(ctx context.Context, subjectID SubjectID, token string) (bool, error)
	DeleteAll(ctx context.Context, subjectID SubjectID) (int64, error)
	DeleteAllExcept(ctx context.Context, subjectID SubjectID, keepToken string) (int64, error)
	DeleteBySessionID(ctx context.Context, subjectID SubjectID, sessionID int64) (bool, error)
	Ban(ctx context.Context, subjectID SubjectID, sessionID int64, reason string) (bool, error)
	Unban(ctx context.Context, subjectID SubjectID, sessionID int64) (bool, error)
	IsBanned(ctx context.Context, token string) (bool, error)
}

// PasswordResetStore reserves the neutral password-reset boundary for progressive migration.
type PasswordResetStore interface {
	Upsert(ctx context.Context, token PasswordResetToken) error
	GetByEmail(ctx context.Context, email string) (PasswordResetToken, error)
	DeleteByEmail(ctx context.Context, email string) error
}

// ConfirmationStore reserves the neutral confirmation-code boundary for progressive migration.
type ConfirmationStore interface {
	SaveCode(ctx context.Context, subjectID SubjectID, purpose string, code string) error
	ConfirmCode(ctx context.Context, subjectID SubjectID, purpose string, code string) error
}

type PasswordHasher interface {
	GenerateHash(password string) ([]byte, error)
	CompareHash(passwordHash string, password string) error
}

type TokenIssuer interface {
	GenerateTokenPair(subject Subject) (*TokenPair, error)
}

type SessionIssuer interface {
	CreateSession(ctx context.Context, subject Subject) (*AuthSession, error)
}

type TxManager interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// ProfileLookup resolves host-owned projection data for a canonical subject.
type ProfileLookup interface {
	GetBySubjectID(ctx context.Context, subjectID SubjectID) (Profile, error)
}

// ProfileProvisioner creates or restores host projections for canonical subjects.
type ProfileProvisioner interface {
	ProvisionForSubject(ctx context.Context, subject Subject) (Profile, error)
}

// ProfileProjectionWriter applies auth-side projection changes back into a host.
type ProfileProjectionWriter interface {
	MarkPhoneConfirmed(ctx context.Context, subjectID SubjectID, confirmedAt time.Time) error
}

// StaticSubjectCredentials reads password data directly from Subject compatibility fields.
type StaticSubjectCredentials struct{}

func (StaticSubjectCredentials) GetPasswordHash(_ context.Context, subject Subject) (string, error) {
	return subject.PasswordHash, nil
}
