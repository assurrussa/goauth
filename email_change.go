package goauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const emailChangeSecretPurpose = "email-change"

// RequestEmailChange is a trusted host API. The host must authorize the actor
// and require fresh authentication before calling it. Local-password HTTP flows
// should use RequestEmailChangeWithPassword instead.
func (r *Runtime) RequestEmailChange(ctx context.Context, subjectID SubjectID, newEmail string) error {
	return r.requestEmailChange(ctx, subjectID, newEmail, nil)
}

// RequestEmailChangeWithPreviousEmailNotice is a trusted host API. Like
// RequestEmailChange, the host must authorize the actor and require fresh
// authentication. previousEmail must be a canonical, already verified host
// address read under the same auth transaction, never an untrusted form value.
// A nonempty value must exactly match the locked pre-change target snapshot.
// Empty retains the existing RequestEmailChange behavior. A successful issuance
// atomically queues a credential-free notice; no mail is sent in the transaction.
// An uncertain commit must not be blindly retried as a new issuance.
func (r *Runtime) RequestEmailChangeWithPreviousEmailNotice(
	ctx context.Context, subjectID SubjectID, newEmail, previousEmail string,
) error {
	return r.requestEmailChangeWithPreviousEmailNotice(ctx, subjectID, newEmail, nil, previousEmail)
}

func (r *Runtime) requestEmailChange(
	ctx context.Context,
	subjectID SubjectID,
	newEmail string,
	expected *Account,
) error {
	return r.requestEmailChangeWithPreviousEmailNotice(ctx, subjectID, newEmail, expected, "")
}

func (r *Runtime) requestEmailChangeWithPreviousEmailNotice(
	ctx context.Context,
	subjectID SubjectID,
	newEmail string,
	expected *Account,
	previousEmail string,
) error {
	if previousEmail != "" {
		normalizedPrevious, err := NormalizeEmail(previousEmail)
		if err != nil || normalizedPrevious != previousEmail {
			return ErrInvalidIdentifier
		}
	}
	scope, target, err := r.emailChangeTarget(ctx)
	if err != nil {
		return err
	}
	if r.notificationDelivery == NotificationDeliveryDisabled {
		return ErrNotificationDeliveryDisabled
	}
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
	var account Account
	if expected != nil {
		// Keep the credential-verified snapshot. Reloading it here would let a
		// concurrent password/security change silently upgrade stale proof.
		account = *expected
	} else {
		account, err = r.store.GetAccount(ctx, subjectID)
		if err != nil {
			return fmt.Errorf("get email change account: %w", err)
		}
	}
	if account.Subject.Status != SubjectStatusActive {
		return ErrAccountUnavailable
	}
	if scope == "" && (account.PrimaryEmail.ID == "" || account.PrimaryEmail.Scheme != IdentifierSchemeEmail) {
		return ErrInvalidIdentifier
	}
	if scope == "" && account.PrimaryEmail.NormalizedValue == normalized.Value {
		return ErrEmailChangeSameValue
	}
	code, err := r.generateEmailCode()
	if err != nil {
		return err
	}
	rateDigest, err := r.secretCodec.DigestActive("rate-limit:email-change", subjectID.String())
	if err != nil {
		return err
	}
	changeID := uuid.NewString()
	var outcomeErr error
	err = r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		// Revalidate the pre-transaction snapshot while holding the same subject
		// lock used by password, status, email and logout-all mutations.
		if err := r.lockExpectedAccount(txCtx, account); err != nil {
			return err
		}
		now := r.now().UTC()
		record := EmailChangeRecord{
			ID:                 changeID,
			SubjectID:          subjectID,
			NewDisplayValue:    displayEmail,
			NewNormalizedValue: normalized.Value,
			RateDigest:         rateDigest,
			MaxAttempts:        5,
			ExpiresAt:          now.Add(r.emailChangeTTL),
			CreatedAt:          now,
		}
		record, err = r.sealEmailChangeRecord(txCtx, target, record, account.Subject.SecurityVersion, code)
		if err != nil {
			return err
		}
		if err := validateEmailChangeNoticeRecipient(previousEmail, account, target, record.TargetSnapshot); err != nil {
			return err
		}
		issue, err := r.issueEmailChange(txCtx, record, EmailChallengeLimits{
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
			outcomeErr = r.limited(ErrConfirmationResendDelay, issue.RetryAt)
			return nil
		default:
			outcomeErr = r.limited(ErrConfirmationRateLimited, issue.RetryAt)
			return nil
		}
		if err := r.enqueueNotification(txCtx, "email_change", account, Notification{
			Template: "email_change",
			To:       displayEmail,
			Data:     emailChangeNotificationData(scope, code, r.emailChangeTTL),
		}, notificationMetadata{referenceID: changeID, validUntil: now.Add(r.emailChangeTTL)}); err != nil {
			return err
		}
		if previousEmail != "" {
			// This is a historical security notice, not a challenge: it must
			// remain deliverable after confirmation or a later issuance.
			if err := r.enqueueNotification(txCtx, "email_change_requested", account, Notification{
				Template: "email_change_requested",
				To:       previousEmail,
				Data:     emailChangedNotificationData(scope),
			}, notificationMetadata{referenceID: changeID}); err != nil {
				return err
			}
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
	scope, _, err := r.emailChangeTarget(ctx)
	if err != nil {
		return PendingEmailChange{}, err
	}
	pending, err := r.pendingEmailChange(ctx, subjectID, scope)
	if err != nil {
		return PendingEmailChange{}, fmt.Errorf("get pending email change: %w", err)
	}

	return pending, nil
}

func (r *Runtime) ConfirmEmailChange(ctx context.Context, subjectID SubjectID, code string) (Account, error) {
	scope, target, err := r.emailChangeTarget(ctx)
	if err != nil {
		return Account{}, err
	}
	if r.notificationDelivery == NotificationDeliveryDisabled {
		return Account{}, ErrNotificationDeliveryDisabled
	}
	if subjectID.IsZero() {
		return Account{}, ErrInvalidConfirmationCode
	}
	code = strings.TrimSpace(code)
	if !validEmailChangeCode(code) {
		return Account{}, ErrInvalidConfirmationCode
	}
	var account Account
	var outcomeErr error
	err = r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		previous, err := r.lockActiveAccount(txCtx, subjectID)
		if err != nil {
			if errors.Is(err, ErrAccountNotFound) {
				return ErrEmailChangeNotFound
			}
			return err
		}
		now := r.now().UTC()
		record, previousEmail, err := r.emailChangeConfirmation(txCtx, previous, scope, target)
		if err != nil {
			return err
		}
		digests, err := r.emailChangeDigests(record, code)
		if err != nil {
			return err
		}
		result, err := r.verifyEmailChange(txCtx, EmailChangeVerifyRequest{
			SubjectID: subjectID, Digests: digests, Now: now,
			Scope: scope, RecordID: record.ID, ExpectedSecurityVersion: record.ExpectedSecurityVersion,
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
		if target != nil {
			if err := target.ApplyVerifiedEmailChange(
				txCtx, subjectID, record.TargetSnapshot, record.NewNormalizedValue, now,
			); err != nil {
				return err
			}
		}
		// An account without a previous host alias has no previous recipient.
		if previousEmail != "" {
			if err := r.enqueueNotification(txCtx, "email_changed", result.Account, Notification{
				Template: "email_changed",
				Data:     emailChangedNotificationData(scope),
				// The previous mailbox must learn about a recovery-address change.
				// It receives no confirmation code or other credential.
				To: previousEmail,
			}); err != nil {
				return err
			}
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


// validateEmailChangeNoticeRecipient binds a trusted host recipient to the
// exact pre-change snapshot captured under the subject lock.
func validateEmailChangeNoticeRecipient(
	previousEmail string, account Account, target EmailChangeTarget, snapshot EmailChangeTargetSnapshot,
) error {
	if previousEmail == "" {
		return nil
	}
	capturedEmail := snapshot.NormalizedEmail
	if target == nil {
		if !account.EmailVerified() {
			return ErrInvalidIdentifier
		}
		capturedEmail = account.PrimaryEmail.NormalizedValue
	}
	if capturedEmail == "" || previousEmail != capturedEmail {
		return ErrSecurityVersionMismatch
	}
	return nil
}
