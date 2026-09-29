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
	allowed, err := r.takeIdentifierRateLimit(ctx, "credential_verify", identifier, r.loginRateLimit)
	if err != nil {
		return Account{}, fmt.Errorf("check credential verification rate limit: %w", err)
	}
	if !allowed {
		return Account{}, ErrAuthenticationRateLimited
	}
	record, lookupErr := r.store.FindLocalAccount(ctx, identifier)
	passwordPHC := record.PasswordPHC
	if lookupErr != nil || record.Account.IsZero() || passwordPHC == "" {
		passwordPHC = r.dummyPasswordPHC
	}
	passwordErr := r.hasher.VerifyPassword(passwordPHC, credential.Password)
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

func (r *Runtime) ChangePassword(ctx context.Context, request ChangePasswordRequest) (Account, error) {
	if request.SubjectID.IsZero() {
		return Account{}, ErrAccountNotFound
	}
	if err := r.passwordPolicy.Validate(request.NewPassword); err != nil {
		return Account{}, err
	}
	record, err := r.store.GetLocalAccount(ctx, request.SubjectID)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return Account{}, ErrCurrentPasswordInvalid
		}
		return Account{}, fmt.Errorf("get local credential: %w", err)
	}
	if err := r.hasher.VerifyPassword(record.PasswordPHC, request.CurrentPassword); err != nil {
		if isPasswordVerificationFailure(err) {
			return Account{}, fmt.Errorf("verify current password: %w", err)
		}
		return Account{}, ErrCurrentPasswordInvalid
	}
	passwordErr := r.hasher.VerifyPassword(record.PasswordPHC, request.NewPassword)
	if passwordErr == nil {
		return Account{}, ErrPasswordUnchanged
	}
	if isPasswordVerificationFailure(passwordErr) {
		return Account{}, fmt.Errorf("compare replacement password: %w", passwordErr)
	}
	passwordPHC, err := r.hasher.HashPassword(request.NewPassword)
	if err != nil {
		return Account{}, fmt.Errorf("hash replacement password: %w", err)
	}
	now := r.now().UTC()
	var account Account
	var outcomeErr error
	err = r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		result, err := r.store.ChangePassword(txCtx, PasswordChangeStoreRequest{
			SubjectID:           request.SubjectID,
			ExpectedPasswordPHC: record.PasswordPHC,
			NewPasswordPHC:      passwordPHC,
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
		if err := r.enqueueNotification(txCtx, "password_changed", result.Account, Notification{
			Template: "password_changed",
			To:       result.Account.PrimaryEmail.DisplayValue,
		}); err != nil {
			return err
		}
		if err := r.recordAudit(txCtx, SecurityEvent{
			Type:      SecurityEventPasswordChanged,
			SubjectID: request.SubjectID,
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
