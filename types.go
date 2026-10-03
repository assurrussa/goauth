package goauth

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SubjectID is the canonical identifier shared by every goauth relation.
type SubjectID uuid.UUID

var NilSubjectID = SubjectID(uuid.Nil)

func NewSubjectID() SubjectID {
	return SubjectID(uuid.New())
}

func ParseSubjectID(value string) (SubjectID, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return NilSubjectID, fmt.Errorf("%w: %w", ErrInvalidSubjectID, err)
	}

	return SubjectID(parsed), nil
}

func MustParseSubjectID(value string) SubjectID {
	parsed, err := ParseSubjectID(value)
	if err != nil {
		panic(err)
	}

	return parsed
}

func (id SubjectID) String() string {
	return uuid.UUID(id).String()
}

func (id SubjectID) Value() (driver.Value, error) {
	return id.String(), nil
}

func (id *SubjectID) Scan(source any) error {
	return (*uuid.UUID)(id).Scan(source)
}

func (id SubjectID) MarshalText() ([]byte, error) {
	return uuid.UUID(id).MarshalText()
}

func (id *SubjectID) UnmarshalText(value []byte) error {
	return (*uuid.UUID)(id).UnmarshalText(value)
}

func (id SubjectID) IsZero() bool {
	return id == NilSubjectID
}

func (id SubjectID) Validate() error {
	if id.IsZero() {
		return ErrInvalidSubjectID
	}

	return nil
}

type SubjectStatus string

const (
	SubjectStatusActive    SubjectStatus = "active"
	SubjectStatusSuspended SubjectStatus = "suspended"
	SubjectStatusDisabled  SubjectStatus = "disabled"
)

func (s SubjectStatus) Validate() error {
	switch s {
	case SubjectStatusActive, SubjectStatusSuspended, SubjectStatusDisabled:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidSubjectStatus, s)
	}
}

// Subject is the canonical security principal. Profile, identifiers,
// credentials, memberships, and permissions deliberately live elsewhere.
type Subject struct {
	ID              SubjectID
	Status          SubjectStatus
	SecurityVersion int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (s Subject) IsZero() bool {
	return s.ID.IsZero()
}

type IdentifierScheme string

const IdentifierSchemeEmail IdentifierScheme = "email"

func (s IdentifierScheme) Validate() error {
	value := string(s)
	if value == "" || len(value) > 32 {
		return fmt.Errorf("%w: %q", ErrInvalidIdentifierScheme, value)
	}

	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9') || (i > 0 && (r == '_' || r == '-')) {
			continue
		}

		return fmt.Errorf("%w: %q", ErrInvalidIdentifierScheme, value)
	}

	return nil
}

type IdentifierInput struct {
	Scheme IdentifierScheme
	Value  string
}

// Identifier stores both a display value and its scheme-specific canonical
// value. VerifiedAt is the only source for verification claims.
type Identifier struct {
	ID              string
	SubjectID       SubjectID
	Scheme          IdentifierScheme
	DisplayValue    string
	NormalizedValue string
	VerifiedAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (i Identifier) IsVerified() bool {
	return i.VerifiedAt != nil && !i.VerifiedAt.IsZero()
}

type BasicProfile struct {
	Username    string
	DisplayName string
	GivenName   string
	FamilyName  string
}

type Account struct {
	Subject Subject
	// PrimaryEmail is zero for deliberately provisioned email-less identities.
	PrimaryEmail Identifier
	Profile      BasicProfile
}

func (a Account) IsZero() bool {
	return a.Subject.IsZero()
}

func (a Account) EmailVerified() bool {
	return a.PrimaryEmail.Scheme == IdentifierSchemeEmail && a.PrimaryEmail.IsVerified()
}

type Credential struct {
	Identifier IdentifierInput
	Password   string
}

type Realm string

const (
	RealmUser  Realm = "user"
	RealmAdmin Realm = "admin"
)

func (r Realm) Validate() error {
	value := string(r)
	if value == "" || len(value) > 32 {
		return fmt.Errorf("%w: %q", ErrInvalidRealm, value)
	}

	for i, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (i > 0 && ch >= '0' && ch <= '9') || (i > 0 && (ch == '_' || ch == '-')) {
			continue
		}

		return fmt.Errorf("%w: %q", ErrInvalidRealm, value)
	}

	return nil
}

type SessionScope string

const (
	SessionScopeAuthenticated SessionScope = "authenticated"
	SessionScopeConfirmation  SessionScope = "confirmation"
)

type Session struct {
	ID              string
	SubjectID       SubjectID
	Realm           Realm
	Scope           SessionScope
	SecurityVersion int64
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

func (s Session) Active(now time.Time) bool {
	return s.RevokedAt == nil && now.Before(s.ExpiresAt)
}

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	Session          Session
}

type AuthContext struct {
	SubjectID       SubjectID
	Realm           Realm
	Scope           SessionScope
	SessionID       string
	SecurityVersion int64
	Claims          map[string]any
}

type EmailChallengePurpose string

const EmailChallengePurposeVerification EmailChallengePurpose = "verification"

func (p EmailChallengePurpose) Validate() error {
	if p != EmailChallengePurposeVerification {
		return fmt.Errorf("%w: %q", ErrInvalidChallengePurpose, p)
	}

	return nil
}

type SecurityEventType string

const (
	SecurityEventLocalIdentityProvisioned SecurityEventType = "local_identity.provisioned"
	SecurityEventLocalIdentityImported    SecurityEventType = "local_identity.imported"
	SecurityEventLoginFailed              SecurityEventType = "login.failed"
	SecurityEventRefreshReplay            SecurityEventType = "refresh.replay"
	SecurityEventPasswordResetIssued      SecurityEventType = "password_reset.issued"
	SecurityEventPasswordResetUsed        SecurityEventType = "password_reset.used"
	SecurityEventPasswordChanged          SecurityEventType = "password.changed"
	SecurityEventTrustedLocalPasswordSet  SecurityEventType = "password.trusted_set"
	SecurityEventLocalIdentityRenamed     SecurityEventType = "local_identity.renamed"
	SecurityEventSubjectRetired           SecurityEventType = "subject.retired"
	SecurityEventEmailChallengeIssued     SecurityEventType = "email_challenge.issued"
	SecurityEventEmailVerified            SecurityEventType = "email.verified"
	SecurityEventEmailChangeIssued        SecurityEventType = "email_change.issued"
	SecurityEventEmailChanged             SecurityEventType = "email.changed"
	SecurityEventSessionRevoked           SecurityEventType = "session.revoked"
	SecurityEventSessionsRevoked          SecurityEventType = "sessions.revoked"
	SecurityEventSubjectStatusChanged     SecurityEventType = "subject.status_changed"
	SecurityEventIdentityLinked           SecurityEventType = "identity.linked"
)

type SecurityEvent struct {
	Type       SecurityEventType
	SubjectID  SubjectID
	Realm      Realm
	At         time.Time
	Attributes map[string]string
}

type ExternalIdentity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Profile       BasicProfile
}

type IdentityLink struct {
	ID              string
	SubjectID       SubjectID
	Issuer          string
	ExternalSubject string
	EmailNormalized string
	EmailVerified   bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}

	result := make(map[string]string, len(values))
	for key, value := range values {
		result[strings.TrimSpace(key)] = value
	}

	return result
}
