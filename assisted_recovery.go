package goauth

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/url"
	"strings"
	"time"
)

const AssistedRecoveryLifetime = 15 * time.Minute

var (
	ErrAssistedRecoveryUnavailable = errors.New("assisted recovery unavailable")
	ErrAssistedRecoveryDenied      = errors.New("assisted recovery denied")
)

// AssistedRecoveryAuthorization is evaluated inside the security transaction.
// The host must check its dedicated recovery permission and independently
// verified identity evidence. A name or possession of the new email is not
// identity evidence. Neither this interface nor Auth may come from request JSON.
type AssistedRecoveryAuthorization interface {
	AuthorizeAssistedRecovery(ctx context.Context, auth AuthContext, subject SubjectID, reason, reference string) error
}

// AssistedRecoveryRequest identifies an existing local account. Starting a
// recovery never changes its email, password, MFA, roles, or sessions.
type AssistedRecoveryRequest struct {
	Auth              AuthContext
	SubjectID         SubjectID
	NewEmail          string
	Password          string
	Code              string
	Reason            string
	EvidenceReference string
}

// AssistedRecoveryRecord contains only a keyed token digest. Stores must join
// AuthTransaction, lock subject before record, and bind the invitation to the
// exact security version and current primary email. Later issuance supersedes
// earlier invitations without modifying account security state.
type AssistedRecoveryRecord struct {
	OwnerCLI        bool
	Scope           string
	TargetVersion   int64
	Selector        string
	SubjectID       SubjectID
	ActorID         SubjectID
	Digest          SecretDigest
	SecurityVersion int64
	OldEmail        string
	NewEmail        string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

type AssistedRecoveryStore interface {
	CreateAssistedRecovery(ctx context.Context, record AssistedRecoveryRecord) error
	FindAssistedRecoverySubject(ctx context.Context, selector string) (SubjectID, error)
	LockAssistedRecovery(ctx context.Context, selector string) (AssistedRecoveryRecord, error)
	// CompleteAssistedRecovery performs exact-record CAS, preserves identity and
	// roles, changes email and password together, advances security version, and
	// invalidates all sessions, refresh families and recovery links atomically.
	CompleteAssistedRecovery(
		ctx context.Context, record AssistedRecoveryRecord, passwordPHC string, now time.Time,
	) (Account, error)
}

// AssistedRecovery is a transport-neutral, explicitly configured host service.
// Hosts must expose initiation only to authenticated administrators with CSRF
// protection and must never log request secrets or invitation URLs.
type AssistedRecovery struct {
	runtime       *Runtime
	store         AssistedRecoveryStore
	authorization AssistedRecoveryAuthorization
	completionURL string
	scope         string
	target        AssistedRecoveryTarget
}

// AssistedRecoveryTarget is a host-owned email projection on this exact auth
// database. Every method joins the managed transaction. Read must lock its
// target; Replace must use email/version CAS and invalidate host sessions.
// VerifyFactor must preserve enrollment and durably charge incorrect attempts.
// PreparePassword must apply the host's existing issuance policy and hash budget.
type AssistedRecoveryTarget interface {
	ReadAssistedRecoveryTarget(ctx context.Context, subject SubjectID) (AssistedRecoveryTargetSnapshot, error)
	ReplaceAssistedRecoveryTarget(
		ctx context.Context, subject SubjectID, snapshot AssistedRecoveryTargetSnapshot, email string, now time.Time,
	) error
	VerifyAssistedRecoveryFactor(ctx context.Context, subject SubjectID, code string, now time.Time) (bool, error)
	PrepareAssistedRecoveryPassword(ctx context.Context, subject SubjectID, password string) (string, error)
}

type AssistedRecoveryTargetSnapshot struct {
	Email   string
	Version int64
}

func NewAssistedRecovery(
	runtime *Runtime, authorization AssistedRecoveryAuthorization, completionURL string,
) (*AssistedRecovery, error) {
	if runtime == nil || authorization == nil || runtime.notificationDelivery == NotificationDeliveryDisabled {
		return nil, ErrAssistedRecoveryUnavailable
	}
	store, ok := runtime.store.(AssistedRecoveryStore)
	if !ok {
		return nil, ErrAssistedRecoveryUnavailable
	}
	if _, ok := runtime.authTransaction.(ownedMFATransaction); !ok {
		return nil, ErrAssistedRecoveryUnavailable
	}
	if err := validatePasswordResetURL(completionURL); err != nil {
		return nil, err
	}
	return &AssistedRecovery{runtime: runtime, store: store, authorization: authorization, completionURL: completionURL}, nil
}

// NewScopedAssistedRecovery handles a host projection with distinct MFA and
// issuance policy. Scope and target are trusted assembly configuration.
func NewScopedAssistedRecovery(
	runtime *Runtime, authorization AssistedRecoveryAuthorization, completionURL, scope string,
	target AssistedRecoveryTarget,
) (*AssistedRecovery, error) {
	if target == nil || strings.TrimSpace(scope) != scope || scope == "" || len(scope) > 64 {
		return nil, ErrAssistedRecoveryUnavailable
	}
	service, err := NewAssistedRecovery(runtime, authorization, completionURL)
	if err != nil {
		return nil, err
	}
	service.scope, service.target = scope, target
	return service, nil
}

func (s *AssistedRecovery) Initiate(ctx context.Context, request AssistedRecoveryRequest) error {
	r := s.runtime
	newEmail, err := NormalizeEmail(request.NewEmail)
	if err != nil || request.SubjectID.IsZero() || request.Auth.Realm != RealmAdmin ||
		request.SubjectID == request.Auth.SubjectID ||
		!validAssistedRecoveryReason(request.Reason, request.EvidenceReference) || len(request.Code) > 128 {
		return ErrAssistedRecoveryDenied
	}
	// Verify a fresh password outside the final transaction, then bind its
	// snapshot to the current actor session/version under the final locks.
	var actor Account
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		var err error
		actor, err = r.lockMFASession(txctx, request.Auth)
		return err
	})
	if err != nil {
		return err
	}
	if err := r.limitPasswordChange(ctx, actor.Subject.ID); err != nil {
		return err
	}
	credential, err := r.store.GetLocalAccount(ctx, actor.Subject.ID)
	if err != nil {
		return err
	}
	if !sameMFALoginAccount(actor, credential.Account) {
		return ErrSecurityVersionMismatch
	}
	if err := r.hasher.verifyCredential(credential.PasswordPHC, request.Password, credential.PasswordInputPolicy); err != nil {
		if isPasswordVerificationFailure(err) {
			return err
		}
		return ErrCurrentPasswordInvalid
	}
	proofDeadline := r.now().Add(5 * time.Minute)
	token, digest, err := r.secretCodec.Generate("assisted-recovery")
	if err != nil {
		return err
	}
	denied := false
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		current, err := r.lockMFASession(txctx, request.Auth)
		if err != nil {
			return err
		}
		if !sameMFALoginAccount(actor, current) || !r.now().Before(proofDeadline) {
			return ErrSecurityVersionMismatch
		}
		if err := s.authorization.AuthorizeAssistedRecovery(txctx, request.Auth, request.SubjectID,
			request.Reason, request.EvidenceReference); err != nil {
			return err
		}
		verified, err := s.verifyExistingMFA(txctx, actor.Subject.ID, request.Code)
		if err != nil {
			return err
		}
		if !verified {
			denied = true
			return nil
		}
		return s.issueLocked(txctx, request, actor.Subject.ID, newEmail, token, digest, false)
	})
	if err != nil {
		return err
	}
	if denied {
		return ErrAssistedRecoveryDenied
	}
	return nil
}

type AssistedRecoveryCompletion struct {
	Token       string
	NewPassword string
	Code        string
}

func (s *AssistedRecovery) Complete(ctx context.Context, request AssistedRecoveryCompletion) error {
	r := s.runtime
	if len(request.Token) > 1024 || len(request.Code) > 128 {
		return ErrAssistedRecoveryDenied
	}
	token, digest, err := r.secretCodec.Parse(strings.TrimSpace(request.Token), "assisted-recovery")
	if err != nil {
		return ErrAssistedRecoveryDenied
	}
	subject, err := s.store.FindAssistedRecoverySubject(ctx, token.selector)
	if err != nil {
		return ErrAssistedRecoveryDenied
	}
	// Charge a durable subject bucket before expensive hashing. Failed MFA
	// attempts below also commit; they must not roll back with a denial error.
	if err := r.limitPasswordChange(ctx, subject); err != nil {
		return err
	}
	var phc string
	if s.target != nil || r.passwordResetRecipientResolver == nil {
		phc, err = s.preparePassword(ctx, subject, request.NewPassword)
		if err != nil {
			return err
		}
	}
	return s.completePrepared(ctx, request, token, digest, subject, phc)
}

func (s *AssistedRecovery) completePrepared(ctx context.Context, request AssistedRecoveryCompletion,
	token opaqueToken, digest SecretDigest, subject SubjectID, phc string,
) error {
	r := s.runtime
	denied := false
	err := r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		account, err := r.lockActiveAccount(txctx, subject)
		if err != nil {
			return err
		}
		record, err := s.store.LockAssistedRecovery(txctx, token.selector)
		if err != nil {
			return err
		}
		snapshot, err := s.targetSnapshot(txctx, account)
		if err != nil {
			return err
		}
		now := r.now().UTC()
		if record.Selector != token.selector || record.Scope != s.scope || record.OldEmail != snapshot.Email ||
			record.TargetVersion != snapshot.Version || !validAssistedRecoveryRecord(record, account, digest, now) {
			denied = true
			return nil
		}
		phc, err = s.resolveCompletionPassword(txctx, account, request.NewPassword, phc)
		if err != nil {
			return err
		}

		verified, err := s.verifyTargetMFA(txctx, subject, request.Code)
		if err != nil {
			return err
		}
		if !verified {
			denied = true
			return nil
		}
		// Sample time again after waiting for factor locks/verification.
		now = r.now().UTC()
		if !now.Before(record.ExpiresAt) {
			denied = true
			return nil
		}
		if s.target != nil {
			if err := s.target.ReplaceAssistedRecoveryTarget(txctx, subject, snapshot, record.NewEmail, now); err != nil {
				return err
			}
		}
		changed, err := s.store.CompleteAssistedRecovery(txctx, record, phc, now)
		if err != nil {
			return err
		}
		if err := r.enqueueNotification(txctx, "assisted_recovery_completed", changed, Notification{
			Template: "assisted_recovery_completed", To: record.OldEmail,
		}); err != nil {
			return err
		}
		return r.recordAudit(txctx, SecurityEvent{
			Type: "assisted_recovery.completed", SubjectID: subject, At: now,
			Attributes: map[string]string{"actor_subject_id": record.ActorID.String()},
		})
	})
	if err != nil {
		return err
	}
	if denied {
		return ErrAssistedRecoveryDenied
	}
	return nil
}

func (s *AssistedRecovery) resolveCompletionPassword(
	ctx context.Context, account Account, password, phc string) (string, error,
) {
	if phc != "" || s.runtime.passwordResetRecipientResolver == nil {
		return phc, nil
	}
	phc, err := s.runtime.passwordResetRecipientResolver.PreparePasswordResetPassword(ctx, account, password)
	if err != nil {
		return "", err
	}
	if phc != "" {
		return phc, nil
	}
	return s.preparePassword(ctx, account.Subject.ID, password)
}

func (s *AssistedRecovery) targetSnapshot(ctx context.Context, account Account) (AssistedRecoveryTargetSnapshot, error) {
	if s.target != nil {
		return s.target.ReadAssistedRecoveryTarget(ctx, account.Subject.ID)
	}
	if account.PrimaryEmail.ID == "" {
		return AssistedRecoveryTargetSnapshot{}, ErrAssistedRecoveryDenied
	}
	return AssistedRecoveryTargetSnapshot{
		Email:   account.PrimaryEmail.NormalizedValue,
		Version: account.Subject.SecurityVersion,
	}, nil
}

func (s *AssistedRecovery) preparePassword(ctx context.Context, subject SubjectID, password string) (string, error) {
	if s.target != nil {
		return s.target.PrepareAssistedRecoveryPassword(ctx, subject, password)
	}
	if err := s.runtime.passwordPolicy.Validate(password); err != nil {
		return "", err
	}
	return s.runtime.hasher.HashPassword(password)
}

func (s *AssistedRecovery) verifyTargetMFA(ctx context.Context, subject SubjectID, code string) (bool, error) {
	if s.target != nil {
		return s.target.VerifyAssistedRecoveryFactor(ctx, subject, code, s.runtime.now())
	}
	return s.verifyExistingMFA(ctx, subject, code)
}

func (s *AssistedRecovery) verifyExistingMFA(ctx context.Context, subject SubjectID, code string) (bool, error) {
	r := s.runtime
	admission, ok := r.store.(MFALocalAdmissionStore)
	if !ok {
		return false, ErrAssistedRecoveryUnavailable
	}
	required, err := admission.LocalMFARequired(ctx, subject)
	if err != nil {
		return false, err
	}
	if !required {
		return true, nil
	}
	if r.mfaStore == nil || r.mfaCodec == nil {
		return false, ErrMFAUnavailable
	}
	factor, err := r.mfaStore.LockMFAFactor(ctx, subject)
	if err != nil {
		return false, err
	}
	decision, err := VerifyMFAFactorLocked(ctx, r.mfaStore, r.mfaCodec, subject, factor, code, r.now())
	return decision == MFAFactorVerified, err
}

func validAssistedRecoveryReason(reason, reference string) bool {
	return strings.TrimSpace(reason) != "" && len(reason) <= 512 && strings.TrimSpace(reference) != "" &&
		len(reference) <= 256 &&
		!strings.ContainsAny(reason+reference, "\x00\r\n")
}

func validAssistedRecoveryRecord(record AssistedRecoveryRecord, account Account, digest SecretDigest, now time.Time) bool {
	return record.Selector != "" && record.SubjectID == account.Subject.ID && !record.ActorID.IsZero() &&
		record.OwnerCLI == (record.ActorID == record.SubjectID) && validAssistedRecoveryMailbox(record.OldEmail) &&
		validAssistedRecoveryMailbox(record.NewEmail) &&
		account.Subject.Status == SubjectStatusActive && record.SecurityVersion > 0 &&
		record.SecurityVersion == account.Subject.SecurityVersion &&
		record.OldEmail != "" && (record.Scope != "" ||
		record.OldEmail == account.PrimaryEmail.NormalizedValue) && record.NewEmail != record.OldEmail && record.TargetVersion > 0 &&
		!record.CreatedAt.IsZero() && !record.CreatedAt.After(now) && record.ExpiresAt.After(record.CreatedAt) &&
		record.ExpiresAt.Sub(record.CreatedAt) <= AssistedRecoveryLifetime && now.Before(record.ExpiresAt) &&
		digest.KeyID == record.Digest.KeyID && len(digest.Digest) == 32 && hmac.Equal(digest.Digest, record.Digest.Digest)
}

// AssistedRecoveryOwnerAuthorization is server-CLI authority only. Implementations
// must lock the owner population and verify this is the sole active owner.
// Never expose this capability through an HTTP route.
type AssistedRecoveryOwnerAuthorization interface {
	AuthorizeOwnerAssistedRecovery(ctx context.Context, subject SubjectID) error
}

type AssistedRecoveryOwnerRequest struct {
	SubjectID    SubjectID
	NewEmail     string
	Reason       string
	Confirmation string
}

func AssistedRecoveryOwnerConfirmation(subject SubjectID, email string) string {
	return "RECOVER ACCOUNT " + subject.String() + " TO " + email
}

func (s *AssistedRecovery) InitiateOwner(
	ctx context.Context, request AssistedRecoveryOwnerRequest, authorization AssistedRecoveryOwnerAuthorization,
) error {
	email, err := NormalizeEmail(request.NewEmail)
	if err != nil || authorization == nil || request.SubjectID.IsZero() ||
		request.Confirmation != AssistedRecoveryOwnerConfirmation(request.SubjectID, email) ||
		!validAssistedRecoveryReason(request.Reason, "server-cli") {
		return ErrAssistedRecoveryDenied
	}
	token, digest, err := s.runtime.secretCodec.Generate("assisted-recovery")
	if err != nil {
		return err
	}
	return s.runtime.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		if err := authorization.AuthorizeOwnerAssistedRecovery(txctx, request.SubjectID); err != nil {
			return err
		}
		return s.issueLocked(txctx, AssistedRecoveryRequest{
			SubjectID: request.SubjectID, Reason: request.Reason,
			EvidenceReference: "server-cli",
		}, request.SubjectID, email, token, digest, true)
	})
}

func ownerCLIString(owner bool) string {
	if owner {
		return "true"
	}
	return "false"
}

func (s *AssistedRecovery) issueLocked(ctx context.Context, request AssistedRecoveryRequest, actorID SubjectID,
	newEmail string, token opaqueToken, digest SecretDigest, ownerCLI bool,
) error {
	r := s.runtime
	target, err := r.lockActiveAccount(ctx, request.SubjectID)
	if err != nil {
		return err
	}
	local, err := r.store.GetLocalAccount(ctx, request.SubjectID)
	if err != nil {
		return err
	}
	if local.PasswordPHC == "" || !sameMFALoginAccount(target, local.Account) {
		return ErrAssistedRecoveryDenied
	}
	snapshot, err := s.targetSnapshot(ctx, target)
	if err != nil {
		return err
	}
	if snapshot.Email == "" || snapshot.Email == newEmail {
		return ErrAssistedRecoveryDenied
	}
	now := r.now().UTC()
	record := AssistedRecoveryRecord{
		OwnerCLI: ownerCLI, Scope: s.scope, TargetVersion: snapshot.Version, Selector: token.selector,
		SubjectID: request.SubjectID, ActorID: actorID,
		Digest: digest, SecurityVersion: target.Subject.SecurityVersion, OldEmail: snapshot.Email,
		NewEmail: newEmail, CreatedAt: now, ExpiresAt: now.Add(AssistedRecoveryLifetime),
	}
	if err := s.store.CreateAssistedRecovery(ctx, record); err != nil {
		return err
	}
	link, err := url.Parse(s.completionURL)
	if err != nil {
		return err
	}
	// A fragment keeps the invitation secret out of ordinary page requests.
	fragment := url.Values{}
	fragment.Set("token", token.raw)
	link.Fragment = fragment.Encode()
	if err := r.enqueueNotification(ctx, "assisted_recovery", target, Notification{
		Template: "assisted_recovery", To: newEmail, Data: map[string]string{"url": link.String()},
	}, notificationMetadata{referenceID: record.Selector, validUntil: record.ExpiresAt}); err != nil {
		return err
	}
	return r.recordAudit(ctx, SecurityEvent{
		Type: "assisted_recovery.issued", SubjectID: request.SubjectID, Realm: RealmAdmin, At: now,
		Attributes: map[string]string{
			"owner_cli":        ownerCLIString(ownerCLI),
			"actor_subject_id": actorID.String(), "reason": request.Reason, "identity_evidence_reference": request.EvidenceReference,
		},
	})
}

func validAssistedRecoveryMailbox(value string) bool {
	normalized, err := NormalizeEmail(value)
	return err == nil && normalized == value
}
