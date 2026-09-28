package goauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const emailChangeSecretPurpose = "email-change"

func (r *Runtime) RequestEmailChange(ctx context.Context, subjectID SubjectID, newEmail string) error {
	if subjectID.IsZero() {
		return ErrAccountNotFound
	}
	displayEmail := strings.TrimSpace(newEmail)
	normalized, err := r.normalizeIdentifier(ctx, IdentifierInput{
		Scheme: IdentifierSchemeEmail,
		Value:  displayEmail,
	})
	if err != nil {
		return err
	}
	account, err := r.store.GetAccount(ctx, subjectID)
	if err != nil {
		return fmt.Errorf("get email change account: %w", err)
	}
	if account.Subject.Status != SubjectStatusActive {
		return ErrAccountUnavailable
	}
	if account.PrimaryEmail.NormalizedValue == normalized.Value {
		return ErrEmailChangeSameValue
	}
	code, err := r.generateEmailCode()
	if err != nil {
		return err
	}
	digest, err := r.secretCodec.DigestActive(emailChangeSecretPurpose, code)
	if err != nil {
		return err
	}
	rateDigest, err := r.secretCodec.DigestActive("rate-limit:email-change", subjectID.String())
	if err != nil {
		return err
	}
	now := r.now().UTC()
	changeID := uuid.NewString()
	var outcomeErr error
	err = r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		issue, err := r.store.IssueEmailChange(txCtx, EmailChangeRecord{
			ID:                 changeID,
			SubjectID:          subjectID,
			NewDisplayValue:    displayEmail,
			NewNormalizedValue: normalized.Value,
			Digest:             digest,
			RateDigest:         rateDigest,
			MaxAttempts:        5,
			ExpiresAt:          now.Add(r.emailChangeTTL),
			CreatedAt:          now,
		}, EmailChallengeLimits{
			MinResendInterval: time.Minute,
			PerHour:           5,
			PerDay:            10,
		})
		if err != nil {
			return fmt.Errorf("issue email change: %w", err)
		}
		switch issue.Status {
		case EmailChangeIssued:
		case EmailChangeSameValue:
			outcomeErr = ErrEmailChangeSameValue
			return nil
		case EmailChangeWait:
			outcomeErr = ErrConfirmationResendDelay
			return nil
		default:
			outcomeErr = ErrConfirmationRateLimited
			return nil
		}
		if err := r.enqueueNotification(txCtx, "email_change", account, Notification{
			Template: "email_change",
			To:       displayEmail,
			Data: map[string]string{
				"code":                 code,
				notificationExpiresKey: r.emailChangeTTL.String(),
			},
		}, notificationMetadata{referenceID: changeID, validUntil: now.Add(r.emailChangeTTL)}); err != nil {
			return err
		}
		return r.recordAudit(txCtx, SecurityEvent{
			Type:      SecurityEventEmailChangeIssued,
			SubjectID: subjectID,
			At:        now,
		})
	})
	if err != nil {
		return err
	}
	return outcomeErr
}

func (r *Runtime) PendingEmailChange(ctx context.Context, subjectID SubjectID) (PendingEmailChange, error) {
	if subjectID.IsZero() {
		return PendingEmailChange{}, ErrEmailChangeNotFound
	}
	pending, err := r.store.GetPendingEmailChange(ctx, subjectID, r.now().UTC())
	if err != nil {
		return PendingEmailChange{}, fmt.Errorf("get pending email change: %w", err)
	}

	return pending, nil
}

func (r *Runtime) ConfirmEmailChange(ctx context.Context, subjectID SubjectID, code string) (Account, error) {
	if subjectID.IsZero() {
		return Account{}, ErrInvalidConfirmationCode
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return Account{}, ErrInvalidConfirmationCode
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return Account{}, ErrInvalidConfirmationCode
		}
	}
	digests, err := r.secretCodec.DigestAll(emailChangeSecretPurpose, code)
	if err != nil {
		return Account{}, err
	}
	now := r.now().UTC()
	var account Account
	var outcomeErr error
	err = r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		result, err := r.store.VerifyEmailChange(txCtx, EmailChangeVerifyRequest{
			SubjectID: subjectID,
			Digests:   digests,
			Now:       now,
		})
		if err != nil {
			return fmt.Errorf("verify email change: %w", err)
		}
		switch result.Status {
		case EmailChangeVerified:
		case EmailChangeInvalid:
			outcomeErr = ErrInvalidConfirmationCode
			return nil
		case EmailChangeExpired:
			outcomeErr = ErrConfirmationExpired
			return nil
		case EmailChangeAttemptsUsed:
			outcomeErr = ErrConfirmationAttempts
			return nil
		case EmailChangeNotFound:
			outcomeErr = ErrEmailChangeNotFound
			return nil
		default:
			outcomeErr = ErrInvalidConfirmationCode
			return nil
		}
		if err := r.enqueueNotification(txCtx, "email_changed", result.Account, Notification{
			Template: "email_changed",
			To:       result.Account.PrimaryEmail.DisplayValue,
		}); err != nil {
			return err
		}
		if err := r.recordAudit(txCtx, SecurityEvent{
			Type:      SecurityEventEmailChanged,
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
