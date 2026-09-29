package goauth

import (
	"context"
	"errors"
	"fmt"
)

// PasswordEmailChangeRequest binds reauthentication to the actor selected by the
// trusted host. Never populate SubjectID from an unauthenticated request body.
type PasswordEmailChangeRequest struct {
	SubjectID       SubjectID
	CurrentPassword string
	NewEmail        string
}

// RequestEmailChangeWithPassword verifies this subject's current local password
// before issuing an email-change challenge. The caller still owns session and
// actor-to-target authorization. SSO-only accounts need an explicit host-owned
// recent-IdP-authentication flow through RequestEmailChange; there is no fallback.
func (r *Runtime) RequestEmailChangeWithPassword(ctx context.Context, request PasswordEmailChangeRequest) error {
	if request.SubjectID.IsZero() {
		return ErrAccountNotFound
	}
	record, err := r.store.GetLocalAccount(ctx, request.SubjectID)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return ErrCurrentPasswordInvalid
		}
		return fmt.Errorf("get email change credential: %w", err)
	}
	if record.Account.Subject.ID != request.SubjectID || record.PasswordPHC == "" {
		return ErrCurrentPasswordInvalid
	}
	if record.Account.Subject.Status != SubjectStatusActive {
		return ErrAccountUnavailable
	}
	// Preserve the existing durable password_change bucket. Email and password
	// changes must not offer independent budgets for guessing the same password.
	// Admission commits before the later auth transaction, including on denial.
	if err := r.limitPasswordChange(ctx, request.SubjectID); err != nil {
		return fmt.Errorf("check email change reauthentication limit: %w", err)
	}
	if err := r.hasher.VerifyPassword(record.PasswordPHC, request.CurrentPassword); err != nil {
		if isPasswordVerificationFailure(err) {
			return fmt.Errorf("verify email change password: %w", err)
		}
		return ErrCurrentPasswordInvalid
	}
	return r.requestEmailChange(ctx, request.SubjectID, request.NewEmail, &record.Account)
}
