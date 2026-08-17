package core

import (
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"

	"github.com/assurrussa/goauth/internal/legacy/shared"
)

type SubjectID = shared.SubjectID

var ErrInvalidSubjectID = errors.New("invalid subject id")

type SubjectKind string

const (
	SubjectKindUnknown SubjectKind = ""
	SubjectKindAccount SubjectKind = "account"
	SubjectKindUser    SubjectKind = "user"
	SubjectKindAdmin   SubjectKind = "admin"
)

// Credential carries transport-neutral authentication input.
type Credential struct {
	Email    string
	Password string
}

// Subject is the canonical identity shape reused across auth transports.
// ID, Kind, Email, and PasswordVersion are the stable auth fields.
// PublicID carries the host-facing uuid projection identifier.
// Optional legacy/native fields are kept for compatibility adapters.
type Subject struct {
	ID               SubjectID
	Kind             SubjectKind
	Email            string
	ConfirmedEmailAt *time.Time
	PasswordVersion  int64
	Roles            []string
	Permissions      map[string][]string

	PublicID  sharedtypes.UserID
	NumericID int64
	Version   int64

	Username   string
	Name       string
	LastName   string
	FatherName string
	Gender     *int
	Birthday   sql.NullTime
	Data       *ProfileData
	PreviewID  int64

	PasswordHash string
}

type SubjectProfilePatch struct {
	Username   *string
	Name       *string
	LastName   *string
	FatherName *string
	Gender     *int
	Birthday   *sql.NullTime
}

func (s Subject) IsZero() bool {
	return s.ID.IsZero() && s.Email == "" && s.PublicID.IsZero() && s.NumericID == 0
}

func (s Subject) AuthSubjectID() SubjectID {
	if !s.ID.IsZero() {
		return s.ID
	}

	return shared.SubjectIDNil
}

func (s Subject) CanonicalID() string {
	id := s.AuthSubjectID()
	if id.IsZero() {
		return ""
	}

	return id.String()
}

func (s Subject) Clone() Subject {
	clone := s
	clone.Roles = slices.Clone(s.Roles)
	if len(s.Permissions) == 0 {
		clone.Permissions = nil
		return clone
	}

	perms := maps.Clone(s.Permissions)
	for key, values := range perms {
		perms[key] = slices.Clone(values)
	}
	clone.Permissions = perms

	return clone
}

func ParseSubjectID(subjectID SubjectID) (SubjectKind, string, bool) {
	if subjectID.IsZero() {
		return SubjectKindUnknown, "", false
	}

	return SubjectKindUnknown, subjectID.String(), true
}

func ParseSubjectIDString(value string) (SubjectID, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return shared.SubjectIDNil, ErrInvalidSubjectID
	}

	subjectID, err := shared.Parse[shared.SubjectID](value)
	if err != nil {
		return shared.SubjectIDNil, fmt.Errorf("%w: %w", ErrInvalidSubjectID, err)
	}

	return subjectID, nil
}

func MustParseSubjectIDString(value string) SubjectID {
	subjectID, err := ParseSubjectIDString(value)
	if err != nil {
		panic(err)
	}

	return subjectID
}

// AuthSession is a neutral session/token record used by adapter boundaries.
type AuthSession struct {
	ID              string
	SubjectID       SubjectID
	Kind            SubjectKind
	Token           string
	NumericID       int64
	PasswordVersion int64
	Reason          *string
	BannedAt        *time.Time
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

func (s AuthSession) IsZero() bool {
	return s.Token == "" && s.SubjectID.IsZero() && s.NumericID == 0
}

// TokenPair is the neutral token response shape for token-based transports.
type TokenPair struct {
	SubjectID        SubjectID
	Kind             SubjectKind
	Domain           string
	AccessToken      string
	RefreshToken     string
	ExpiresIn        int64
	ExpiresRefreshIn int64
}

type PasswordResetToken struct {
	Email     string
	SubjectID SubjectID
	Token     string
	CreatedAt time.Time
}

// AuthContext carries canonical auth data independent from HTTP/session details.
type AuthContext struct {
	Subject Subject
	Session *AuthSession
}

// ProfileData keeps host-specific role/permission projection metadata.
type ProfileData struct {
	Role        string              `json:"role,omitempty"`
	Permissions map[string][]string `json:"permissions,omitempty"`
}

// Profile is the reusable host projection shape used by auth workflows.
// Host apps keep owning their tables, but workflows can pass this shape through
// adapters without importing app-specific packages. PublicID maps to the
// existing host-facing `uuid` storage and JSON field.
type Profile struct {
	ID              int64              `json:"id" db:"id"`
	SubjectID       SubjectID          `json:"-" db:"subject_id"`
	PublicID        sharedtypes.UserID `json:"uuid" db:"uuid"`
	Email           string             `json:"email" db:"email"`
	Username        *string            `json:"username" db:"username"`
	Name            string             `json:"name" db:"name"`
	LastName        *string            `json:"lastName" db:"last_name"`
	FatherName      *string            `json:"fatherName" db:"father_name"`
	Bio             *string            `json:"bio" db:"bio"`
	Gender          *int               `json:"gender" db:"gender"`
	Birthday        sql.NullTime       `json:"birthday" db:"birthday"`
	Phone           *int64             `json:"phone" db:"phone"`
	PasswordHash    string             `json:"-" db:"password_hash"`
	Version         int64              `json:"version" db:"version"`
	PasswordVersion int64              `json:"-" db:"pwd_version"`
	// PasswordChangedVersion is kept for compatibility with legacy user/admin projections.
	PasswordChangedVersion int64 `json:"-" db:"pwd_version"`

	TelegramChatID   sql.NullInt64  `json:"telegramChatId,omitempty" db:"telegram_chat_id"`
	TelegramUsername sql.NullString `json:"telegramUsername,omitempty" db:"telegram_username"`
	Data             *ProfileData   `json:"data,omitempty" db:"data,omitempty"`

	ConfirmedEmailAt sql.NullTime `json:"confirmedEmailAt" db:"confirmed_email_at"`
	ConfirmedPhoneAt sql.NullTime `json:"confirmedPhoneAt" db:"confirmed_phone_at"`
	CreatedAt        time.Time    `json:"createdAt" db:"created_at"`
	UpdatedAt        time.Time    `json:"updatedAt" db:"updated_at"`
	DeletedAt        sql.NullTime `json:"deletedAt,omitempty" db:"deleted_at"`
}

func (p *Profile) GetRole() string {
	if p == nil || p.Data == nil {
		return ""
	}

	return p.Data.Role
}

func (p *Profile) GetPermissions() map[string][]string {
	if p == nil || p.Data == nil {
		return nil
	}

	return p.Data.Permissions
}

func (p Profile) IsEmailConfirmed() bool {
	return p.ConfirmedEmailAt.Valid && !p.ConfirmedEmailAt.Time.IsZero()
}

func (p Profile) IsPhoneConfirmed() bool {
	return p.ConfirmedPhoneAt.Valid && !p.ConfirmedPhoneAt.Time.IsZero()
}

func (p Profile) AuthSubjectID() SubjectID {
	if !p.SubjectID.IsZero() {
		return p.SubjectID
	}

	return shared.SubjectIDNil
}

type ConfirmationStatus struct {
	EmailConfirmed    bool
	PhoneConfirmed    bool
	TelegramConfirmed bool
}

type ConfirmationRecord struct {
	ID               int64
	SubjectID        SubjectID
	ConfirmationType shared.ConfirmationType
	ConfirmationInfo string
	Purpose          shared.ConfirmationPurpose
	ConfirmedAt      time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type ConfirmationInfo struct {
	Profile Profile
	Status  ConfirmationStatus
}
