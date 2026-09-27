package goauth

import (
	"context"
	"time"
)

type SecretDigest struct {
	KeyID  string
	Digest []byte
}

type LocalAccountRecord struct {
	Account     Account
	PasswordPHC string
}

type AccountStore interface {
	CreateLocalAccount(ctx context.Context, record LocalAccountRecord) (Account, error)
	FindAccount(ctx context.Context, identifier IdentifierInput) (Account, error)
	FindLocalAccount(ctx context.Context, identifier IdentifierInput) (LocalAccountRecord, error)
	GetLocalAccount(ctx context.Context, subjectID SubjectID) (LocalAccountRecord, error)
	GetAccount(ctx context.Context, subjectID SubjectID) (Account, error)
	UpdateBasicProfile(ctx context.Context, subjectID SubjectID, profile BasicProfile, now time.Time) (Account, error)
	ChangePassword(ctx context.Context, request PasswordChangeStoreRequest) (PasswordChangeStoreResult, error)
}

type PasswordChangeStoreRequest struct {
	SubjectID           SubjectID
	ExpectedPasswordPHC string
	NewPasswordPHC      string
	Now                 time.Time
}

type PasswordChangeStoreStatus string

const (
	PasswordChangeStoreSucceeded PasswordChangeStoreStatus = "succeeded"
	PasswordChangeStoreConflict  PasswordChangeStoreStatus = "conflict"
	PasswordChangeStoreMissing   PasswordChangeStoreStatus = "missing"
)

type PasswordChangeStoreResult struct {
	Status  PasswordChangeStoreStatus
	Account Account
}

type SSOAccountRecord struct {
	Account Account
	Link    IdentityLink
}

type IdentityLinkStore interface {
	ResolveIdentityLink(ctx context.Context, issuer, externalSubject string) (Account, IdentityLink, error)
	CreateSSOAccount(ctx context.Context, record SSOAccountRecord) (Account, IdentityLink, error)
	LinkIdentity(ctx context.Context, link IdentityLink) (IdentityLink, error)
}

type SessionRecord struct {
	Session          Session
	FamilyID         string
	RefreshSelector  string
	RefreshDigest    SecretDigest
	RefreshExpiresAt time.Time
}

type RefreshRotationRequest struct {
	CurrentSelector string
	CurrentDigest   SecretDigest
	NextSelector    string
	NextDigest      SecretDigest
	NextExpiresAt   time.Time
	Now             time.Time
}

type RefreshRotationStatus string

const (
	RefreshRotationSucceeded RefreshRotationStatus = "succeeded"
	RefreshRotationInvalid   RefreshRotationStatus = "invalid"
	RefreshRotationExpired   RefreshRotationStatus = "expired"
	RefreshRotationRevoked   RefreshRotationStatus = "revoked"
	RefreshRotationReplayed  RefreshRotationStatus = "replayed"
)

type RefreshRotationResult struct {
	Status   RefreshRotationStatus
	Account  Account
	Session  Session
	FamilyID string
}

type SessionSecurity struct {
	Session        Session
	SubjectStatus  SubjectStatus
	CurrentVersion int64
}

type SessionStore interface {
	CreateSession(ctx context.Context, record SessionRecord) error
	RotateRefresh(ctx context.Context, request RefreshRotationRequest) (RefreshRotationResult, error)
	IntrospectSession(ctx context.Context, sessionID string) (SessionSecurity, error)
	RevokeSession(ctx context.Context, subjectID SubjectID, sessionID string, now time.Time) (bool, error)
	RevokeSubjectSessions(ctx context.Context, subjectID SubjectID, now time.Time) (int64, error)
	SetSubjectStatus(ctx context.Context, subjectID SubjectID, status SubjectStatus, now time.Time) (Subject, error)
}

type PasswordResetRecord struct {
	SubjectID SubjectID
	Selector  string
	Digest    SecretDigest
	// Expected fields reject a reset issued from a stale account lookup.
	ExpectedNormalizedEmail string
	ExpectedSecurityVersion int64
	ExpiresAt               time.Time
	CreatedAt               time.Time
}

type PasswordResetConsumeStatus string

const (
	PasswordResetConsumed PasswordResetConsumeStatus = "consumed"
	PasswordResetInvalid  PasswordResetConsumeStatus = "invalid"
	PasswordResetExpired  PasswordResetConsumeStatus = "expired"
	PasswordResetUsed     PasswordResetConsumeStatus = "used"
)

type PasswordResetConsumeRequest struct {
	Selector    string
	Digest      SecretDigest
	PasswordPHC string
	Now         time.Time
}

type PasswordResetConsumeResult struct {
	Status  PasswordResetConsumeStatus
	Account Account
}

type PasswordResetStore interface {
	CreatePasswordReset(ctx context.Context, record PasswordResetRecord) error
	ConsumePasswordReset(ctx context.Context, request PasswordResetConsumeRequest) (PasswordResetConsumeResult, error)
}

type EmailChallengeRecord struct {
	ID           string
	SubjectID    SubjectID
	IdentifierID string
	// Runtime supplies these together so a store can reject a challenge if
	// the account changes after the caller reads its email destination.
	ExpectedNormalizedEmail string
	ExpectedSecurityVersion int64
	Purpose                 EmailChallengePurpose
	Digest                  SecretDigest
	RateDigest              SecretDigest
	MaxAttempts             int
	ExpiresAt               time.Time
	CreatedAt               time.Time
}

type EmailChallengeLimits struct {
	MinResendInterval time.Duration
	PerHour           int
	PerDay            int
}

type EmailChallengeIssueStatus string

const (
	EmailChallengeIssued      EmailChallengeIssueStatus = "issued"
	EmailChallengeWait        EmailChallengeIssueStatus = "wait"
	EmailChallengeHourlyLimit EmailChallengeIssueStatus = "hourly_limit"
	EmailChallengeDailyLimit  EmailChallengeIssueStatus = "daily_limit"
)

type EmailChallengeIssueResult struct {
	Status  EmailChallengeIssueStatus
	RetryAt time.Time
}

type EmailChallengeVerifyStatus string

const (
	EmailChallengeVerified        EmailChallengeVerifyStatus = "verified"
	EmailChallengeInvalid         EmailChallengeVerifyStatus = "invalid"
	EmailChallengeExpired         EmailChallengeVerifyStatus = "expired"
	EmailChallengeAttemptsUsed    EmailChallengeVerifyStatus = "attempts_used"
	EmailChallengeAlreadyVerified EmailChallengeVerifyStatus = "already_verified"
)

type EmailChallengeVerifyRequest struct {
	SubjectID SubjectID
	Purpose   EmailChallengePurpose
	Digests   []SecretDigest
	Now       time.Time
}

type EmailChallengeVerifyResult struct {
	Status   EmailChallengeVerifyStatus
	Account  Account
	Attempts int
}

type EmailChallengeStore interface {
	IssueEmailChallenge(
		ctx context.Context,
		record EmailChallengeRecord,
		limits EmailChallengeLimits,
	) (EmailChallengeIssueResult, error)
	VerifyEmailChallenge(ctx context.Context, request EmailChallengeVerifyRequest) (EmailChallengeVerifyResult, error)
}

type EmailChangeRecord struct {
	ID                 string
	SubjectID          SubjectID
	NewDisplayValue    string
	NewNormalizedValue string
	Digest             SecretDigest
	RateDigest         SecretDigest
	MaxAttempts        int
	ExpiresAt          time.Time
	CreatedAt          time.Time
}

type EmailChangeIssueStatus string

const (
	EmailChangeIssued      EmailChangeIssueStatus = "issued"
	EmailChangeWait        EmailChangeIssueStatus = "wait"
	EmailChangeHourlyLimit EmailChangeIssueStatus = "hourly_limit"
	EmailChangeDailyLimit  EmailChangeIssueStatus = "daily_limit"
	EmailChangeSameValue   EmailChangeIssueStatus = "same_value"
)

type EmailChangeIssueResult struct {
	Status  EmailChangeIssueStatus
	RetryAt time.Time
}

type PendingEmailChange struct {
	ID              string
	SubjectID       SubjectID
	NewDisplayValue string
	Attempts        int
	MaxAttempts     int
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

type EmailChangeVerifyStatus string

const (
	EmailChangeVerified     EmailChangeVerifyStatus = "verified"
	EmailChangeInvalid      EmailChangeVerifyStatus = "invalid"
	EmailChangeExpired      EmailChangeVerifyStatus = "expired"
	EmailChangeAttemptsUsed EmailChangeVerifyStatus = "attempts_used"
	EmailChangeNotFound     EmailChangeVerifyStatus = "not_found"
)

type EmailChangeVerifyRequest struct {
	SubjectID SubjectID
	Digests   []SecretDigest
	Now       time.Time
}

type EmailChangeVerifyResult struct {
	Status   EmailChangeVerifyStatus
	Account  Account
	Attempts int
}

type EmailChangeStore interface {
	IssueEmailChange(
		ctx context.Context,
		record EmailChangeRecord,
		limits EmailChallengeLimits,
	) (EmailChangeIssueResult, error)
	GetPendingEmailChange(ctx context.Context, subjectID SubjectID, now time.Time) (PendingEmailChange, error)
	VerifyEmailChange(ctx context.Context, request EmailChangeVerifyRequest) (EmailChangeVerifyResult, error)
}

type RateLimitRequest struct {
	SubjectID SubjectID
	Action    string
	Bucket    SecretDigest
	Window    time.Duration
	Limit     int
	Now       time.Time
}

type RateLimitResult struct {
	Allowed bool
	RetryAt time.Time
}

type RateLimitStore interface {
	TakeRateLimit(ctx context.Context, request RateLimitRequest) (RateLimitResult, error)
}

type RuntimeStore interface {
	AccountStore
	SessionStore
	PasswordResetStore
	EmailChallengeStore
	EmailChangeStore
	IdentityLinkStore
	RateLimitStore
}

type IdentifierResolver interface {
	NormalizeIdentifier(ctx context.Context, input IdentifierInput) (IdentifierInput, error)
}

type IdentifierResolverFunc func(context.Context, IdentifierInput) (IdentifierInput, error)

func (f IdentifierResolverFunc) NormalizeIdentifier(ctx context.Context, input IdentifierInput) (IdentifierInput, error) {
	return f(ctx, input)
}

type MembershipGate interface {
	AllowMembership(ctx context.Context, realm Realm, account Account) error
}

type MembershipGateFunc func(context.Context, Realm, Account) error

func (f MembershipGateFunc) AllowMembership(ctx context.Context, realm Realm, account Account) error {
	return f(ctx, realm, account)
}

type ClaimsEnricher interface {
	EnrichClaims(ctx context.Context, realm Realm, account Account, claims map[string]any) error
}

type ClaimsEnricherFunc func(context.Context, Realm, Account, map[string]any) error

func (f ClaimsEnricherFunc) EnrichClaims(ctx context.Context, realm Realm, account Account, claims map[string]any) error {
	return f(ctx, realm, account, claims)
}

type Notification struct {
	Template string            `json:"template"`
	To       string            `json:"to"`
	Data     map[string]string `json:"data,omitempty"`
}

type NotificationRenderer interface {
	RenderNotification(ctx context.Context, notification Notification) ([]byte, error)
}

type NotificationRendererFunc func(context.Context, Notification) ([]byte, error)

func (f NotificationRendererFunc) RenderNotification(ctx context.Context, notification Notification) ([]byte, error) {
	return f(ctx, notification)
}

type URLBuilder interface {
	PasswordResetURL(ctx context.Context, token string) (string, error)
}

type URLBuilderFunc func(context.Context, string) (string, error)

func (f URLBuilderFunc) PasswordResetURL(ctx context.Context, token string) (string, error) {
	return f(ctx, token)
}

type EncryptedEnvelope struct {
	KeyID          string
	Nonce          []byte
	Ciphertext     []byte
	AdditionalData []byte
	CreatedAt      time.Time
	DeleteAfter    time.Time
}

type EncryptedEvent struct {
	ID          string
	Type        string
	SubjectID   SubjectID
	ReferenceID string
	ValidUntil  time.Time
	Envelope    EncryptedEnvelope
}

type EncryptedEventSink interface {
	EnqueueEncrypted(ctx context.Context, event EncryptedEvent) error
	DeleteEncrypted(ctx context.Context, eventID string) error
	DeleteExpiredEncrypted(ctx context.Context, before time.Time) (int64, error)
}

type AuditSink interface {
	RecordSecurityEvent(ctx context.Context, event SecurityEvent) error
}

type AuditSinkFunc func(context.Context, SecurityEvent) error

func (f AuditSinkFunc) RecordSecurityEvent(ctx context.Context, event SecurityEvent) error {
	return f(ctx, event)
}
