package goauth

import (
	"context"
	"errors"
	"fmt"
)

// PasswordResetRecipientResolver is an optional, privileged host policy for
// recovery addresses. Lookup must find exactly one canonical subject across
// primary email and every host-authorized alias; missing or colliding ownership
// must return ErrAccountNotFound. Neither method may provision a local credential.
//
// Resolve runs with the active canonical subject locked in the auth transaction.
// It must recheck current ownership and return the current authorized destination.
// A nonempty requestedEmail must still belong unambiguously to account.Subject.ID.
// Empty requestedEmail asks for the current password-reset success destination.
// Use the supplied context for all reads. Hosts must serialize alias mutations
// through the same subject lock and invalidate all reset records in that transaction,
// including change-away-and-back, before publishing the mutation.
type PasswordResetRecipientResolver interface {
	LookupPasswordResetSubject(ctx context.Context, normalizedEmail string) (SubjectID, error)
	ResolvePasswordResetRecipient(ctx context.Context, account Account, requestedEmail string) (string, error)
	// PreparePasswordResetPassword applies host policy and returns a prepared PHC.
	// Empty PHC with nil error selects the unchanged Runtime policy and hasher.
	// It runs only after token authentication under the same subject lock. It
	// must not mutate state or log/persist the supplied plaintext password.
	PreparePasswordResetPassword(ctx context.Context, account Account, newPassword string) (string, error)
}

// PasswordResetSubjectStore is the opt-in storage capability required by
// PasswordResetRecipientResolver. The ordinary PasswordResetStore contract is
// unchanged. Implementations must lock the subject, require active status, a
// nonempty current local credential and the exact ExpectedSecurityVersion.
// ExpectedNormalizedEmail must be empty; it is not an alternate identity field.
// Replacement, single-use, expiry and transaction guarantees match CreatePasswordReset.
type PasswordResetSubjectStore interface {
	CreatePasswordResetForSubject(ctx context.Context, record PasswordResetRecord) error
	// Authenticate and lock subject then token before prepare. Recheck expiry
	// with the current configured clock after preparation and before mutation.
	ConsumePasswordResetWithPreparation(ctx context.Context, request PasswordResetConsumeRequest,
		prepare func(context.Context, Account) (string, error)) (PasswordResetConsumeResult, error)
}

func passwordResetRecipientUnavailable(err error) bool {
	return errors.Is(err, ErrAccountNotFound) || errors.Is(err, ErrAccountUnavailable) ||
		errors.Is(err, ErrSubjectRetired) || errors.Is(err, ErrInvalidIdentifier) || errors.Is(err, ErrSecurityVersionMismatch)
}

func (r *Runtime) requestPasswordResetForRecipient(
	ctx context.Context, normalizedEmail string, bind func(context.Context, PasswordResetReceipt) error,
) error {
	subjectID, err := r.passwordResetRecipientResolver.LookupPasswordResetSubject(ctx, normalizedEmail)
	if err != nil {
		if passwordResetRecipientUnavailable(err) {
			return nil
		}
		return fmt.Errorf("lookup password reset subject: %w", err)
	}
	if subjectID.IsZero() {
		return nil
	}
	record, err := r.store.GetLocalAccount(ctx, subjectID)
	if err != nil {
		if passwordResetRecipientUnavailable(err) {
			return nil
		}
		return fmt.Errorf("get password reset local account: %w", err)
	}
	if record.Account.Subject.ID != subjectID || record.Account.Subject.Status != SubjectStatusActive ||
		record.PasswordPHC == "" || record.Account.Subject.SecurityVersion < 1 {
		return nil
	}
	token, digest, err := r.secretCodec.Generate(passwordResetSecretPurpose)
	if err != nil {
		return err
	}
	resetURL, err := r.urlBuilder.PasswordResetURL(ctx, token.raw)
	if err != nil {
		return fmt.Errorf("build password reset URL: %w", err)
	}
	if err := validatePasswordResetURL(resetURL); err != nil {
		return err
	}
	return r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		account, err := r.lockActiveAccount(txCtx, subjectID)
		if err != nil {
			if passwordResetRecipientUnavailable(err) {
				return nil
			}
			return err
		}
		if account.Subject.SecurityVersion != record.Account.Subject.SecurityVersion {
			return nil
		}
		local, err := r.store.GetLocalAccount(txCtx, subjectID)
		if err != nil {
			if passwordResetRecipientUnavailable(err) {
				return nil
			}
			return err
		}
		if local.Account.Subject.ID != subjectID || local.PasswordPHC == "" ||
			local.Account.Subject.SecurityVersion != account.Subject.SecurityVersion {
			return nil
		}
		recipient, err := r.passwordResetRecipientResolver.ResolvePasswordResetRecipient(txCtx, account, normalizedEmail)
		if err != nil {
			if passwordResetRecipientUnavailable(err) {
				return nil
			}
			return fmt.Errorf("resolve password reset recipient: %w", err)
		}
		if _, err := NormalizeEmail(recipient); err != nil {
			return nil
		}
		now := r.now().UTC()
		// NewRuntime checked this optional capability before accepting the policy.
		store, ok := r.store.(PasswordResetSubjectStore)
		if !ok {
			return errors.New("subject-bound password reset store is unavailable")
		}
		if err := store.CreatePasswordResetForSubject(txCtx, PasswordResetRecord{
			SubjectID: subjectID, Selector: token.selector, Digest: digest,
			ExpectedSecurityVersion: account.Subject.SecurityVersion,
			ExpiresAt:               now.Add(r.passwordResetTTL), CreatedAt: now,
		}); err != nil {
			if passwordResetRecipientUnavailable(err) {
				return nil
			}
			return fmt.Errorf("create subject-bound password reset: %w", err)
		}
		if err := r.enqueueNotification(txCtx, "password_reset", account, Notification{
			Template: "password_reset", To: recipient,
			Data: map[string]string{"reset_url": resetURL, notificationExpiresKey: r.passwordResetTTL.String()},
		}, notificationMetadata{referenceID: token.selector, validUntil: now.Add(r.passwordResetTTL)}); err != nil {
			return err
		}
		if err := r.recordAudit(txCtx, SecurityEvent{
			Type: SecurityEventPasswordResetIssued, SubjectID: subjectID, At: now,
		}); err != nil {
			return err
		}
		if bind != nil {
			return bind(txCtx, PasswordResetReceipt{SubjectID: subjectID, Selector: token.selector})
		}
		return nil
	})
}

func (r *Runtime) consumePasswordResetForRecipient(
	ctx context.Context, request PasswordResetConsumeRequest, newPassword string,
) (PasswordResetConsumeResult, string, error) {
	store, ok := r.store.(PasswordResetSubjectStore)
	if !ok {
		return PasswordResetConsumeResult{}, "", errors.New("subject-bound password reset store is unavailable")
	}
	var recipient string
	result, err := store.ConsumePasswordResetWithPreparation(ctx, request,
		func(txCtx context.Context, account Account) (string, error) {
			var err error
			recipient, err = r.passwordResetRecipientResolver.ResolvePasswordResetRecipient(txCtx, account, "")
			if err != nil {
				if passwordResetRecipientUnavailable(err) {
					return "", ErrInvalidToken
				}
				return "", err
			}
			if _, err := NormalizeEmail(recipient); err != nil {
				return "", ErrInvalidToken
			}
			phc, err := r.passwordResetRecipientResolver.PreparePasswordResetPassword(txCtx, account, newPassword)
			if err != nil || phc != "" {
				return phc, err
			}
			if err := r.passwordPolicy.Validate(newPassword); err != nil {
				return "", err
			}
			phc, err = r.hasher.HashPassword(newPassword)
			if err != nil {
				return "", fmt.Errorf("hash replacement password: %w", err)
			}
			return phc, nil
		})
	return result, recipient, err
}
