package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// EmailChangeScope identifies a host-owned recovery-address projection. The
// empty scope retains the primary-email contract. A scope is trusted host
// authority and must never be selected from an untrusted form or URL.
type EmailChangeScope string

type emailChangeScopeContextKey struct{}

// WithEmailChangeScope selects a configured host projection for the existing
// email-change APIs. An unknown nonempty scope fails closed.
func WithEmailChangeScope(ctx context.Context, scope EmailChangeScope) context.Context {
	return context.WithValue(ctx, emailChangeScopeContextKey{}, scope)
}

func EmailChangeScopeFromContext(ctx context.Context) EmailChangeScope {
	scope, _ := ctx.Value(emailChangeScopeContextKey{}).(EmailChangeScope)
	return scope
}

// EmailChangeTargetSnapshot is a versioned host-owned address. An absent
// address may be empty, but its version must remain positive and monotonic.
type EmailChangeTargetSnapshot struct {
	NormalizedEmail string
	Version         int64
}

// EmailChangeTarget must join the Runtime's auth transaction. Snapshot is read
// under the canonical subject lock. Apply must CAS the complete old snapshot,
// write only this projection, and invalidate dependent host security state.
// It must not mutate the subject, primary email, credentials, or issue sessions.
type EmailChangeTarget interface {
	SnapshotEmailChangeTarget(ctx context.Context, subject SubjectID) (EmailChangeTargetSnapshot, error)
	ApplyVerifiedEmailChange(ctx context.Context, subject SubjectID,
		expected EmailChangeTargetSnapshot, newEmail string, now time.Time) error
}

// ScopedEmailChangeStore is an explicit opt-in. Legacy RuntimeStore adapters
// cannot silently treat a host projection as the primary email. Implementations
// share the ordinary subject-wide issuance quota and record-attempt machinery.
type ScopedEmailChangeStore interface {
	IssueScopedEmailChange(ctx context.Context, record EmailChangeRecord,
		limits EmailChallengeLimits) (EmailChangeIssueResult, error)
	GetPendingScopedEmailChange(ctx context.Context, subject SubjectID,
		scope EmailChangeScope, now time.Time) (PendingEmailChange, error)
	VerifyScopedEmailChange(ctx context.Context, request EmailChangeVerifyRequest) (EmailChangeVerifyResult, error)
}

var ErrEmailChangeScopeUnavailable = errors.New("email change scope is unavailable")

func runtimeEmailChangeTargets(
	store RuntimeStore, targets map[EmailChangeScope]EmailChangeTarget,
) (map[EmailChangeScope]EmailChangeTarget, error) {
	if len(targets) == 0 {
		return map[EmailChangeScope]EmailChangeTarget{}, nil
	}
	if _, ok := store.(ScopedEmailChangeStore); !ok {
		return nil, ErrEmailChangeScopeUnavailable
	}
	copyTargets := make(map[EmailChangeScope]EmailChangeTarget, len(targets))
	for scope, target := range targets {
		if !validEmailChangeScope(scope) || target == nil {
			return nil, ErrEmailChangeScopeUnavailable
		}
		copyTargets[scope] = target
	}
	return copyTargets, nil
}

func validEmailChangeScope(scope EmailChangeScope) bool {
	if len(scope) < 1 || len(scope) > 64 {
		return false
	}
	for _, ch := range scope {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' && ch != '.' {
			return false
		}
	}
	return true
}

func (r *Runtime) emailChangeTarget(ctx context.Context) (EmailChangeScope, EmailChangeTarget, error) {
	scope := EmailChangeScopeFromContext(ctx)
	if scope == "" {
		return "", nil, nil
	}
	target := r.emailChangeTargets[scope]
	if target == nil {
		return scope, nil, ErrEmailChangeScopeUnavailable
	}
	if _, ok := r.store.(ScopedEmailChangeStore); !ok {
		return scope, nil, ErrEmailChangeScopeUnavailable
	}
	return scope, target, nil
}

func validEmailChangeSnapshot(snapshot EmailChangeTargetSnapshot) bool {
	if snapshot.Version <= 0 {
		return false
	}
	if snapshot.NormalizedEmail == "" {
		return true
	}
	value, err := NormalizeEmail(snapshot.NormalizedEmail)
	return err == nil && value == snapshot.NormalizedEmail
}

// JSON array encoding provides unambiguous length-delimited fields; no secret
// is logged or persisted outside its HMAC or encrypted notification envelope.
func emailChangeSecret(record EmailChangeRecord, code string) (purpose, secret string, err error) {
	if record.Scope == "" {
		return emailChangeSecretPurpose, code, nil
	}
	data, err := json.Marshal([]string{
		string(record.Scope), record.SubjectID.String(), record.ID,
		strconv.FormatInt(record.ExpectedSecurityVersion, 10), strconv.FormatInt(record.TargetSnapshot.Version, 10),
		record.TargetSnapshot.NormalizedEmail, record.NewNormalizedValue, code,
	})
	return "email-change/host-v1", string(data), err
}

func (r *Runtime) emailChangeDigests(record EmailChangeRecord, code string) ([]SecretDigest, error) {
	purpose, secret, err := emailChangeSecret(record, code)
	if err != nil {
		return nil, err
	}
	return r.secretCodec.DigestAll(purpose, secret)
}

func (r *Runtime) issueEmailChange(
	ctx context.Context, record EmailChangeRecord, limits EmailChallengeLimits,
) (EmailChangeIssueResult, error) {
	if record.Scope == "" {
		return r.store.IssueEmailChange(ctx, record, limits)
	}
	store, ok := r.store.(ScopedEmailChangeStore)
	if !ok {
		return EmailChangeIssueResult{}, ErrEmailChangeScopeUnavailable
	}
	return store.IssueScopedEmailChange(ctx, record, limits)
}

func (r *Runtime) pendingEmailChange(
	ctx context.Context, subject SubjectID, scope EmailChangeScope,
) (PendingEmailChange, error) {
	if scope == "" {
		return r.store.GetPendingEmailChange(ctx, subject, r.now().UTC())
	}
	store, ok := r.store.(ScopedEmailChangeStore)
	if !ok {
		return PendingEmailChange{}, ErrEmailChangeScopeUnavailable
	}
	return store.GetPendingScopedEmailChange(ctx, subject, scope, r.now().UTC())
}

func (r *Runtime) verifyEmailChange(
	ctx context.Context, request EmailChangeVerifyRequest,
) (EmailChangeVerifyResult, error) {
	if request.Scope == "" {
		return r.store.VerifyEmailChange(ctx, request)
	}
	store, ok := r.store.(ScopedEmailChangeStore)
	if !ok {
		return EmailChangeVerifyResult{}, ErrEmailChangeScopeUnavailable
	}
	return store.VerifyScopedEmailChange(ctx, request)
}

func emailChangePendingRecord(pending PendingEmailChange) EmailChangeRecord {
	return EmailChangeRecord{
		ID: pending.ID, SubjectID: pending.SubjectID, Scope: pending.Scope,
		ExpectedSecurityVersion: pending.ExpectedSecurityVersion,
		TargetSnapshot:          pending.TargetSnapshot, NewNormalizedValue: pending.NewNormalizedValue,
	}
}

func emailChangeNotificationData(scope EmailChangeScope, code string, ttl time.Duration) map[string]string {
	data := map[string]string{"code": code, notificationExpiresKey: ttl.String()}
	if scope != "" {
		data["email_change_scope"] = string(scope)
	}
	return data
}

func emailChangedNotificationData(scope EmailChangeScope) map[string]string {
	if scope == "" {
		return nil
	}
	return map[string]string{"email_change_scope": string(scope)}
}

func validEmailChangeCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	return strings.IndexFunc(code, func(ch rune) bool { return ch < '0' || ch > '9' }) < 0
}

func (r *Runtime) sealEmailChangeRecord(ctx context.Context, target EmailChangeTarget,
	record EmailChangeRecord, securityVersion int64, code string,
) (EmailChangeRecord, error) {
	if target != nil {
		snapshot, err := target.SnapshotEmailChangeTarget(ctx, record.SubjectID)
		if err != nil {
			return EmailChangeRecord{}, err
		}
		if !validEmailChangeSnapshot(snapshot) {
			return EmailChangeRecord{}, ErrInvalidIdentifier
		}
		if snapshot.NormalizedEmail == record.NewNormalizedValue {
			return EmailChangeRecord{}, ErrEmailChangeSameValue
		}
		record.Scope = EmailChangeScopeFromContext(ctx)
		record.ExpectedSecurityVersion, record.TargetSnapshot = securityVersion, snapshot
	}
	purpose, secret, err := emailChangeSecret(record, code)
	if err != nil {
		return EmailChangeRecord{}, err
	}
	record.Digest, err = r.secretCodec.DigestActive(purpose, secret)
	return record, err
}

func (r *Runtime) emailChangeConfirmation(ctx context.Context, previous Account,
	scope EmailChangeScope, target EmailChangeTarget,
) (EmailChangeRecord, string, error) {
	record := EmailChangeRecord{SubjectID: previous.Subject.ID}
	if target == nil {
		return record, previous.PrimaryEmail.DisplayValue, nil
	}
	store, ok := r.store.(ScopedEmailChangeStore)
	if !ok {
		return record, "", ErrEmailChangeScopeUnavailable
	}
	// Retain the ordinary store's typed expiry result after its final row lock.
	pending, err := store.GetPendingScopedEmailChange(ctx, previous.Subject.ID, scope, time.Time{})
	if err != nil {
		return record, "", err
	}
	record = emailChangePendingRecord(pending)
	if record.Scope != scope || record.SubjectID != previous.Subject.ID ||
		record.ExpectedSecurityVersion != previous.Subject.SecurityVersion {
		return record, "", ErrSecurityVersionMismatch
	}
	snapshot, err := target.SnapshotEmailChangeTarget(ctx, previous.Subject.ID)
	if err != nil {
		return record, "", err
	}
	if !validEmailChangeSnapshot(snapshot) || snapshot != record.TargetSnapshot {
		return record, "", ErrSecurityVersionMismatch
	}
	return record, snapshot.NormalizedEmail, nil
}
