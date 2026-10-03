package goauth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SetTrustedLocalPasswordRequest replaces an existing local credential without
// its old password. It never creates a credential or changes subject status.
type SetTrustedLocalPasswordRequest struct {
	SubjectID   SubjectID
	NewPassword string
}

// TrustedLocalPasswordStoreRequest binds a privileged replacement to the exact
// credential and security state read before hashing. All expected fields must
// be checked under the canonical subject lock, then the credential lock.
type TrustedLocalPasswordStoreRequest struct {
	SubjectID                   SubjectID
	ExpectedPasswordPHC         string
	ExpectedPasswordInputPolicy PasswordInputPolicy
	ExpectedSecurityVersion     int64
	NewPasswordPHC              string
	Now                         time.Time
}

// TrustedLocalPasswordStore is an optional RuntimeStore capability. A successful
// write must preserve subject status, replace only an existing credential, set
// its input policy to Unicode, increment security version, and invalidate all
// sessions, local/OIDC refresh families, resets and pending email security state.
// Writes must join AuthTransaction, including mandatory Runtime audit/enqueue.
// Missing subjects/credentials return ErrAccountNotFound. Stale security version
// returns ErrSecurityVersionMismatch; stale PHC/policy returns ErrPasswordChangeConflict.
type TrustedLocalPasswordStore interface {
	SetTrustedLocalPassword(ctx context.Context, request TrustedLocalPasswordStoreRequest) (Account, error)
}

var ErrTrustedLocalPasswordUnsupported = errors.New("trusted local password capability is not supported")

// SetTrustedLocalPassword is a privileged host API, never a public reset endpoint.
// The host must authorize and rate-limit its operator and supply actor audit.
// Strict issuance policy and the shared hash budget apply; authentication-attempt
// admission does not. Even identical plaintext advances security version and
// revokes security state. Active, suspended and disabled status are preserved.
//
// Hashing precedes new locks. Call before taking host project locks. This joins
// an outer AuthTransaction: returned state is provisional until that outer call
// succeeds. Reconcile a durable host operation record on ErrOperationOutcomeUnknown
// before retrying, since a repeated successful call advances security state again.
// Required delivery enqueues password_changed only when a primary email exists;
// disabled delivery/email-less identities still require transactional audit.
func (r *Runtime) SetTrustedLocalPassword(ctx context.Context, request SetTrustedLocalPasswordRequest) (Account, error) {
	store, ok := r.store.(TrustedLocalPasswordStore)
	if !ok {
		return Account{}, ErrTrustedLocalPasswordUnsupported
	}
	if request.SubjectID.IsZero() {
		return Account{}, ErrAccountNotFound
	}
	if err := r.passwordPolicy.Validate(request.NewPassword); err != nil {
		return Account{}, err
	}
	record, err := r.store.GetLocalAccount(ctx, request.SubjectID)
	if err != nil {
		return Account{}, fmt.Errorf("get trusted local credential: %w", err)
	}
	passwordPHC, err := r.hasher.HashPassword(request.NewPassword)
	if err != nil {
		return Account{}, fmt.Errorf("hash trusted local password: %w", err)
	}
	var account Account
	err = r.inSecurityTransaction(ctx, func(txCtx context.Context) error {
		now := r.now().UTC()
		changed, err := store.SetTrustedLocalPassword(txCtx, TrustedLocalPasswordStoreRequest{
			SubjectID: request.SubjectID, ExpectedPasswordPHC: record.PasswordPHC,
			ExpectedPasswordInputPolicy: record.PasswordInputPolicy,
			ExpectedSecurityVersion:     record.Account.Subject.SecurityVersion,
			NewPasswordPHC:              passwordPHC, Now: now,
		})
		if err != nil {
			return fmt.Errorf("set trusted local password: %w", err)
		}
		if r.notificationDelivery == NotificationDeliveryRequired && changed.PrimaryEmail.ID != "" {
			if err := r.enqueueNotification(txCtx, "password_changed", changed, Notification{
				Template: "password_changed", To: changed.PrimaryEmail.DisplayValue,
			}); err != nil {
				return err
			}
		}
		if err := r.recordAudit(txCtx, SecurityEvent{
			Type: SecurityEventTrustedLocalPasswordSet, SubjectID: request.SubjectID, At: now,
		}); err != nil {
			return err
		}
		account = changed
		return nil
	})
	if err != nil {
		return Account{}, err
	}
	return account, nil
}
