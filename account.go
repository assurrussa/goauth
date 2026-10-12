package goauth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProvisionTrustedLocalAccount creates a verified local account for an
// operator-controlled bootstrap or seed path. Interactive registration must
// use Register so that the account starts in confirmation scope.
func (r *Runtime) ProvisionTrustedLocalAccount(ctx context.Context, request RegisterRequest) (Account, error) {
	return r.createLocalAccount(ctx, request, true)
}

func (r *Runtime) createLocalAccount(ctx context.Context, request RegisterRequest, trusted bool) (Account, error) {
	record, err := r.prepareLocalAccount(ctx, request, trusted)
	if err != nil {
		return Account{}, err
	}
	var account Account
	err = r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		var writeErr error
		account, writeErr = r.store.CreateLocalAccount(ctx, record)
		return writeErr
	})
	if err != nil {
		return Account{}, err
	}
	return account, nil
}

func (r *Runtime) prepareLocalAccount(
	ctx context.Context,
	request RegisterRequest,
	trustedVerified bool,
) (LocalAccountRecord, error) {
	if err := r.passwordPolicy.Validate(request.Password); err != nil {
		return LocalAccountRecord{}, err
	}
	displayEmail := strings.TrimSpace(request.Email)
	normalized, err := r.normalizeIdentifier(ctx, IdentifierInput{
		Scheme: IdentifierSchemeEmail,
		Value:  displayEmail,
	})
	if err != nil {
		return LocalAccountRecord{}, err
	}
	passwordPHC, err := r.hasher.HashPassword(request.Password)
	if err != nil {
		return LocalAccountRecord{}, fmt.Errorf("hash password: %w", err)
	}
	now := r.now().UTC()
	subjectID := NewSubjectID()
	var verifiedAt *time.Time
	if trustedVerified {
		value := now
		verifiedAt = &value
	}
	record := LocalAccountRecord{
		Account: Account{
			Subject: Subject{
				ID:              subjectID,
				Status:          SubjectStatusActive,
				SecurityVersion: 1,
				CreatedAt:       now,
				UpdatedAt:       now,
			},
			PrimaryEmail: Identifier{
				ID:              uuid.NewString(),
				SubjectID:       subjectID,
				Scheme:          IdentifierSchemeEmail,
				DisplayValue:    displayEmail,
				NormalizedValue: normalized.Value,
				VerifiedAt:      verifiedAt,
				CreatedAt:       now,
				UpdatedAt:       now,
			},
			Profile: request.Profile,
		},
		PasswordPHC: passwordPHC,
	}
	return record, nil
}

func (r *Runtime) GetAccount(ctx context.Context, subjectID SubjectID) (Account, error) {
	if subjectID.IsZero() {
		return Account{}, ErrAccountNotFound
	}
	account, err := r.store.GetAccount(ctx, subjectID)
	if err != nil {
		return Account{}, fmt.Errorf("get account: %w", err)
	}

	return account, nil
}

func (r *Runtime) FindAccount(ctx context.Context, identifier IdentifierInput) (Account, error) {
	normalized, err := r.normalizeIdentifier(ctx, identifier)
	if err != nil {
		return Account{}, err
	}
	account, err := r.store.FindAccount(ctx, normalized)
	if err != nil {
		return Account{}, fmt.Errorf("find account: %w", err)
	}

	return account, nil
}

// VerifyCredential verifies a local credential without creating a session.
// It is intended for recent-authentication checks and trusted bootstrap flows.
func (r *Runtime) VerifyCredential(ctx context.Context, credential Credential) (Account, error) {
	identifier, err := r.normalizeIdentifier(ctx, credential.Identifier)
	if err != nil {
		return Account{}, ErrInvalidCredentials
	}
	allowed, err := r.takeIdentifierRateLimit(ctx, "credential_verify", identifier, r.credentialVerifyRateLimit)
	if err != nil {
		return Account{}, fmt.Errorf("check credential verification rate limit: %w", err)
	}
	if !allowed {
		return Account{}, ErrAuthenticationRateLimited
	}
	record, lookupErr := r.store.FindLocalAccount(ctx, identifier)
	passwordPHC := record.PasswordPHC
	inputPolicy := record.PasswordInputPolicy
	if lookupErr != nil || record.Account.IsZero() || passwordPHC == "" {
		passwordPHC = ""
		inputPolicy = PasswordInputPolicyUnicode
	}
	passwordErr := r.hasher.verifyCredential(passwordPHC, credential.Password, inputPolicy)
	if lookupErr != nil && !errors.Is(lookupErr, ErrAccountNotFound) {
		return Account{}, fmt.Errorf("find local credential: %w", lookupErr)
	}
	if isPasswordVerificationFailure(passwordErr) {
		return Account{}, fmt.Errorf("verify password: %w", passwordErr)
	}
	if lookupErr != nil || passwordErr != nil || record.Account.IsZero() {
		return Account{}, ErrInvalidCredentials
	}
	if record.Account.Subject.Status != SubjectStatusActive {
		return Account{}, ErrAccountUnavailable
	}

	return record.Account, nil
}

func (r *Runtime) UpdateBasicProfile(
	ctx context.Context,
	subjectID SubjectID,
	profile BasicProfile,
) (Account, error) {
	if subjectID.IsZero() {
		return Account{}, ErrAccountNotFound
	}
	account, err := r.store.UpdateBasicProfile(ctx, subjectID, profile, r.now().UTC())
	if err != nil {
		return Account{}, fmt.Errorf("update basic profile: %w", err)
	}

	return account, nil
}

type ChangePasswordRequest struct {
	SubjectID       SubjectID
	CurrentPassword string
	NewPassword     string
}

// PreparedPasswordChange is an opaque, runtime-bound proof of password
// verification and replacement hashing. It expires after five minutes. Hosts
// must keep it in process and must never log, serialize or send it to a client.
// Completion still requires host-owned session authorization.
type PreparedPasswordChange struct {
	runtime             *Runtime
	account             Account
	expectedPHC         string
	expectedInputPolicy PasswordInputPolicy
	replacementPHC      string
	expiresAt           time.Time
}

// String avoids exposing credential hashes through ordinary formatting.
func (PreparedPasswordChange) String() string { return "[prepared password change]" }

// GoString avoids exposing credential hashes through Go-syntax formatting.
func (PreparedPasswordChange) GoString() string { return "[prepared password change]" }

func (r *Runtime) ChangePassword(ctx context.Context, request ChangePasswordRequest) (Account, error) {
	proof, err := r.PreparePasswordChange(ctx, request)
	if err != nil {
		return Account{}, err
	}
	return r.CompletePasswordChange(ctx, request.SubjectID, proof)
}

// PreparePasswordChange performs durable password-attempt admission and hashing
// outside a host transaction. SubjectID must come from the authenticated actor,
// never from an unauthenticated form. No plaintext password is retained.
func (r *Runtime) PreparePasswordChange(ctx context.Context, request ChangePasswordRequest) (*PreparedPasswordChange, error) {
	return r.preparePasswordChange(ctx, request, r)
}

// PreparePasswordChangeWithIssuer uses a trusted host-selected runtime only for
// replacement policy and bounded hashing. Current-credential verification,
// durable admission, proof binding, notification and audit remain with r.
// Never select the issuer from request input. It grants no account-write authority.
func (r *Runtime) PreparePasswordChangeWithIssuer(ctx context.Context, request ChangePasswordRequest,
	issuer *Runtime,
) (*PreparedPasswordChange, error) {
	if issuer == nil || issuer.hasher == nil {
		return nil, ErrPasswordVerificationUnavailable
	}
	return r.preparePasswordChange(ctx, request, issuer)
}

func (r *Runtime) preparePasswordChange(ctx context.Context, request ChangePasswordRequest,
	issuer *Runtime,
) (*PreparedPasswordChange, error) {
	expiresAt := r.now().UTC().Add(5 * time.Minute)
	if request.SubjectID.IsZero() {
		return nil, ErrAccountNotFound
	}
	if err := r.passwordPolicy.Validate(request.NewPassword); err != nil {
		return nil, err
	}
	if err := issuer.passwordPolicy.Validate(request.NewPassword); err != nil {
		return nil, err
	}
	record, err := r.store.GetLocalAccount(ctx, request.SubjectID)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return nil, ErrCurrentPasswordInvalid
		}
		return nil, fmt.Errorf("get local credential: %w", err)
	}
	if record.Account.Subject.ID != request.SubjectID || record.PasswordPHC == "" {
		return nil, ErrCurrentPasswordInvalid
	}
	if record.Account.Subject.Status != SubjectStatusActive {
		return nil, ErrAccountUnavailable
	}
	if err := r.limitPasswordChange(ctx, request.SubjectID); err != nil {
		return nil, fmt.Errorf("check password change rate limit: %w", err)
	}
	if err := r.hasher.verifyCredential(record.PasswordPHC, request.CurrentPassword, record.PasswordInputPolicy); err != nil {
		if isPasswordVerificationFailure(err) {
			return nil, fmt.Errorf("verify current password: %w", err)
		}
		return nil, ErrCurrentPasswordInvalid
	}
	passwordErr := r.hasher.verifyCredential(record.PasswordPHC, request.NewPassword, record.PasswordInputPolicy)
	if passwordErr == nil {
		return nil, ErrPasswordUnchanged
	}
	if isPasswordVerificationFailure(passwordErr) {
		return nil, fmt.Errorf("compare replacement password: %w", passwordErr)
	}
	passwordPHC, err := issuer.hasher.HashPassword(request.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("hash replacement password: %w", err)
	}
	return &PreparedPasswordChange{
		runtime: r, account: record.Account, expectedPHC: record.PasswordPHC,
		replacementPHC: passwordPHC, expectedInputPolicy: record.PasswordInputPolicy, expiresAt: expiresAt,
	}, nil
}

// CompletePasswordChange joins the host auth transaction, revalidates the proof
// under the subject lock, and performs the existing atomic password update,
// session invalidation, notification and audit. The host must authorize its
// current live session and any required second factor in this same transaction.
// The expected subject prevents a proof from being applied to a different actor.
// Success inside an outer transaction is provisional until that owner commits.
func (r *Runtime) CompletePasswordChange(ctx context.Context, subjectID SubjectID,
	proof *PreparedPasswordChange,
) (Account, error) {
	if proof == nil || proof.runtime != r || subjectID.IsZero() ||
		proof.account.Subject.ID != subjectID || !r.now().Before(proof.expiresAt) {
		return Account{}, ErrCurrentPasswordInvalid
	}
	var account Account
	var outcomeErr error
	err := r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		if err := r.lockExpectedAccount(txCtx, proof.account); err != nil {
			if errors.Is(err, ErrSecurityVersionMismatch) {
				return ErrPasswordChangeConflict
			}
			return err
		}
		// Lock waiting must not extend the recent-authentication window.
		if !r.now().Before(proof.expiresAt) {
			return ErrCurrentPasswordInvalid
		}
		current, err := r.store.GetLocalAccount(txCtx, subjectID)
		if err != nil {
			return err
		}
		if current.PasswordPHC != proof.expectedPHC || current.PasswordInputPolicy != proof.expectedInputPolicy {
			return ErrPasswordChangeConflict
		}
		now := r.now().UTC()
		result, err := r.store.ChangePassword(txCtx, PasswordChangeStoreRequest{
			SubjectID:           subjectID,
			ExpectedPasswordPHC: proof.expectedPHC,
			NewPasswordPHC:      proof.replacementPHC,
			Now:                 now,
		})
		if err != nil {
			return fmt.Errorf("change password: %w", err)
		}
		switch result.Status {
		case PasswordChangeStoreSucceeded:
		case PasswordChangeStoreMissing:
			outcomeErr = ErrCurrentPasswordInvalid
			return nil
		default:
			outcomeErr = ErrPasswordChangeConflict
			return nil
		}
		if r.notificationDelivery == NotificationDeliveryRequired && result.Account.PrimaryEmail.ID != "" {
			if err := r.enqueueNotification(txCtx, "password_changed", result.Account, Notification{
				Template: "password_changed",
				To:       result.Account.PrimaryEmail.DisplayValue,
			}); err != nil {
				return err
			}
		}
		if err := r.recordAudit(txCtx, SecurityEvent{
			Type:      SecurityEventPasswordChanged,
			SubjectID: subjectID,
			At:        now,
		}); err != nil {
			return err
		}
		account = result.Account
		return nil
	})
	if err != nil {
		return Account{}, err
	}
	return account, outcomeErr
}

func (r *Runtime) Logout(ctx context.Context, subjectID SubjectID, sessionID string) error {
	if subjectID.IsZero() || strings.TrimSpace(sessionID) == "" {
		return ErrSessionRevoked
	}
	return r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		now := r.now().UTC()
		revoked, err := r.store.RevokeSession(ctx, subjectID, strings.TrimSpace(sessionID), now)
		if err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		if !revoked {
			return ErrSessionRevoked
		}
		return r.recordAudit(ctx, SecurityEvent{Type: SecurityEventSessionRevoked, SubjectID: subjectID, At: now})
	})
}

func (r *Runtime) LogoutAll(ctx context.Context, subjectID SubjectID) (int64, error) {
	if subjectID.IsZero() {
		return 0, ErrAccountNotFound
	}
	var revoked int64
	err := r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		now := r.now().UTC()
		var err error
		revoked, err = r.store.RevokeSubjectSessions(ctx, subjectID, now)
		if err != nil {
			return fmt.Errorf("revoke subject sessions: %w", err)
		}
		return r.recordAudit(ctx, SecurityEvent{
			Type: SecurityEventSessionsRevoked, SubjectID: subjectID, At: now,
			Attributes: map[string]string{"count": strconv.FormatInt(revoked, 10)},
		})
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}
