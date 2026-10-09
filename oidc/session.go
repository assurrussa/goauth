//nolint:tagliatelle // These DTOs use the OIDC wire claim names.
package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/assurrussa/goauth"
)

// SessionBinding is immutable authentication and host authorization evidence.
// PolicyStamp is opaque bounded host-owned version data, never permissions.
// Later reauthentication must not advance an already issued binding's AuthenticatedAt.
type SessionBinding struct {
	SubjectID         string
	SecurityVersion   int64
	ClientID          string
	SessionID         string
	PolicyStamp       string
	AuthenticatedAt   time.Time
	AbsoluteExpiresAt time.Time
}

// BrowserSession carries the current opaque cookie generation, not the raw cookie.
type BrowserSession struct {
	SessionID    string
	CookieDigest string
}

type SessionAuthorizeRequest struct {
	AuthorizeRequest
	Prompt         []string
	MaxAgeSeconds  *int64
	BrowserBinding string
}

// RequestLoginCompletion may only be written by a verified host login transaction.
// It proves password authentication for this exact request and cookie generation.
type RequestLoginCompletion struct {
	SessionID       string
	CookieDigest    string
	AuthenticatedAt time.Time
}

// CanonicalIdentifiers contains current host-authoritative matching identifiers.
// Version 1 requires a case-sensitive canonical login and permits an optional
// lowercase email alias. An alias does not assert verified mailbox ownership.
// Populate only from canonical identifier storage, never display metadata.
// These values are snapshots, not immutable session bindings or permissions.
type CanonicalIdentifiers struct {
	Version    int    `json:"version"`
	Login      string `json:"login"`
	EmailAlias string `json:"email_alias,omitempty"`
}

type SessionProjection struct {
	Identifiers *CanonicalIdentifiers
	ProjectID   string
	Profile     map[string]string
	Project     map[string]string
}

type SessionAdmissionRequest struct {
	ClientID       string
	SessionID      string
	Browser        *BrowserSession
	Expected       *SessionBinding
	ClientRevision int64
}

// SessionAdmissionResult keeps client authentication available even when Allowed
// is false, so a valid owner can revoke or commit required replay/denial effects.
type SessionAdmissionResult struct {
	Client         Client
	ClientRevision int64
	Binding        SessionBinding
	Account        goauth.Account
	Projection     SessionProjection
	Allowed        bool
}

// SessionAdmission locks subject -> project -> client -> grant -> sid using the
// store's owned transaction. No-session starts lock project -> client only and
// must never subsequently acquire a subject lock. Expected is a lookup hint,
// never authority. Disabled clients must have Trusted=false.
type SessionAdmission interface {
	Lock(ctx context.Context, request SessionAdmissionRequest) (SessionAdmissionResult, error)
}

type SessionDiscoveryMetadata struct {
	DiscoveryMetadata
	ClaimsParameterSupported     bool `json:"claims_parameter_supported"`
	RequestParameterSupported    bool `json:"request_parameter_supported"`
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
}

type SessionUserInfo struct {
	UserInfo
	Identifiers *CanonicalIdentifiers `json:"authhub_identifiers,omitempty"`
	ProjectID   string                `json:"project_id"`
	Profile     map[string]string     `json:"authhub_profile,omitempty"`
	Project     map[string]string     `json:"authhub_project,omitempty"`
}

type SessionRequest struct {
	AuthorizationRequest
	ClientRevision  int64
	Prompt          []string
	MaxAgeSeconds   *int64
	BrowserBinding  string
	LoginCompletion *RequestLoginCompletion
	ConsumedAt      *time.Time
}

type SessionCode struct {
	AuthorizationCode
	Binding    SessionBinding
	ConsumedAt *time.Time
	FamilyID   string
}

type SessionRefresh struct {
	RefreshToken
	Binding    SessionBinding
	FamilyID   string
	ConsumedAt *time.Time
}

type SessionFamily struct {
	FamilyID   string
	Binding    SessionBinding
	Scopes     []string
	RevokedAt  *time.Time
	ReplayedAt *time.Time
}

type SessionRevocationReason string

const (
	SessionRevoked SessionRevocationReason = "revoked"
	SessionReplay  SessionRevocationReason = "replay"
)

// ErrSessionStateConflict means a one-way transition lost or was already made.
var ErrSessionStateConflict = errors.New("session OIDC state transition conflict")

// SessionStateStore owns the complete serialized operation. All writes/locks
// require its exact managed transaction; reads are side-effect-free. Expected
// protocol denials requiring durable effects return nil from the callback and
// are released only after confirmed commit. Secrets/results must never leave a
// callback. An unknown commit is not safe to retry.
type SessionStateStore interface {
	InOwnedAuthTransaction(ctx context.Context, callback func(context.Context) error) error
	SaveRequest(ctx context.Context, request SessionRequest) error
	ReadRequest(ctx context.Context, challenge string) (SessionRequest, error)
	MarkLoginComplete(ctx context.Context, challenge, browserBinding string, completion RequestLoginCompletion) error
	ConsumeRequest(ctx context.Context, challenge string) (SessionRequest, error)
	SaveCode(ctx context.Context, code SessionCode) error
	ReadCode(ctx context.Context, code string) (SessionCode, error)
	LockCode(ctx context.Context, code string) (SessionCode, error)
	ConsumeCode(ctx context.Context, code, familyID string, now time.Time) (SessionCode, error)
	ReadRefresh(ctx context.Context, token string) (SessionRefresh, error)
	LockRefresh(ctx context.Context, token string) (SessionRefresh, error)
	SaveRefresh(ctx context.Context, token SessionRefresh) error
	RotateRefresh(ctx context.Context, current, next SessionRefresh, now time.Time) error
	RevokeFamily(ctx context.Context, familyID string, reason SessionRevocationReason, now time.Time) error
	LockFamily(ctx context.Context, familyID string) (SessionFamily, error)
}
