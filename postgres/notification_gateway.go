package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goauth"
)

// The lease CAS commits receipt ownership and payload erasure together. A lost
// commit response can only replay the same original idempotent operation.
func (s *Store) acceptNotificationQueue(
	ctx context.Context, claim notificationClaim, receipt string, now time.Time, poll time.Duration,
) error {
	_, err := s.db.ExecContext(ctx, `UPDATE auth_notification_deliveries
SET state='gateway_accepted', gateway_receipt_id=$3, gateway_accepted_at=$4,
 ciphertext=NULL, nonce='\x'::bytea, additional_data='\x'::bytea,
 lease_token=NULL, leased_until=NULL, next_attempt_at=$5, delivered_at=NULL,
 last_failure=NULL, last_sender_outcome=NULL, last_sender_code=NULL,
 last_sender_http_status=NULL, last_sender_attempt=NULL, last_sender_observed_at=NULL
WHERE id=$1 AND lease_token=$2 AND state='leased' AND gateway_receipt_id IS NULL`,
		claim.event.ID, claim.leaseToken, receipt, now, now.Add(poll))
	if err != nil {
		return fmt.Errorf("persist downstream notification ownership: %w", err)
	}
	return nil
}

func (r *Runtime) reconcileQueuedNotification(ctx context.Context, claim notificationClaim) error {
	now := r.notificationNow().UTC()
	if !now.Before(claim.event.ValidUntil) {
		return r.store.finishNotification(ctx, claim, notificationExpired, "stale", time.Time{})
	}
	sender, ok := r.notificationSender.(goauth.NotificationReconciler)
	var err error
	if ok {
		checkCtx, cancel := context.WithTimeout(ctx, min(r.notificationWorker.SendTimeout, claim.event.ValidUntil.Sub(now)))
		err = sender.ReconcileNotification(checkCtx, goauth.NotificationQueueReceipt{
			ID: claim.event.ID, ReceiptID: claim.receiptID, ValidUntil: claim.event.ValidUntil,
		})
		// A late nil response cannot acknowledge an observation after its
		// bounded window. Snapshot before cancel, which always ends the child.
		if checkErr := checkCtx.Err(); checkErr != nil {
			err = checkErr
		}
		cancel()
	} else {
		err = errors.New("notification reconciler is unavailable")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !r.notificationNow().UTC().Before(claim.event.ValidUntil) {
		return r.store.finishNotification(ctx, claim, notificationExpired, "stale", time.Time{})
	}
	if err == nil {
		return r.store.finishNotification(ctx, claim, notificationDelivered, "", time.Time{})
	}
	if errors.Is(err, goauth.ErrNotificationQueueFailed) {
		return r.store.finishNotification(ctx, claim, notificationExhausted, "gateway_failed", time.Time{})
	}
	// Failure, unknown and mismatched receipt responses are observation failures,
	// never permission to re-submit or claim non-delivery. This also includes the
	// synchronous ErrNotificationRejected sentinel: ownership already transferred,
	// so it cannot retroactively prove that no provider handoff occurred.
	// No send attempt is used.
	_, err = r.store.db.ExecContext(ctx, `UPDATE auth_notification_deliveries
SET state='gateway_accepted',lease_token=NULL,leased_until=NULL,next_attempt_at=$3
WHERE id=$1 AND lease_token=$2 AND state='leased' AND gateway_receipt_id=$4`,
		claim.event.ID, claim.leaseToken, r.notificationNow().UTC().Add(r.notificationWorker.PollInterval), claim.receiptID)
	return err
}

// reconcileLegacyNotification observes only historical, unmarked operations.
// The subject lock serializes invalidation with the metadata check and native
// completion; the CAS still rejects an expired/reclaimed lease. No send budget
// is reserved, and neither the payload nor its key ring is consulted.
func (r *Runtime) reconcileLegacyNotification(ctx context.Context, claim notificationClaim) (bool, error) {
	observer, ok := r.notificationSender.(goauth.LegacyNotificationReconciler)
	if !ok || claim.protocol != "" {
		return false, nil
	}
	now := r.notificationNow().UTC()
	if !now.Before(claim.event.ValidUntil) {
		return true, r.store.finishNotification(ctx, claim, notificationExpired, "stale", time.Time{})
	}
	err := r.store.InAuthTransaction(ctx, func(txCtx context.Context) error {
		return r.observeLegacyNotification(txCtx, claim, observer)
	})
	if errors.Is(err, errLegacyProviderEvidenceUnavailable) {
		return false, nil
	}
	return true, err
}

var errLegacyProviderEvidenceUnavailable = errors.New("legacy provider evidence unavailable")

func (r *Runtime) observeLegacyNotification(
	ctx context.Context, claim notificationClaim, observer goauth.LegacyNotificationReconciler,
) error {
	account, err := r.store.LockAccount(ctx, claim.event.SubjectID)
	if errors.Is(err, goauth.ErrAccountNotFound) || errors.Is(err, goauth.ErrSubjectRetired) {
		return errLegacyProviderEvidenceUnavailable
	}
	if err != nil {
		return err
	}
	if account.Subject.Status != goauth.SubjectStatusActive {
		return errLegacyProviderEvidenceUnavailable
	}
	current, err := r.store.notificationCurrent(ctx, claim.event, r.notificationNow().UTC())
	if err != nil {
		return err
	}
	if !current {
		return errLegacyProviderEvidenceUnavailable
	}
	checkCtx, cancel := context.WithTimeout(ctx, min(r.notificationWorker.SendTimeout,
		claim.event.ValidUntil.Sub(r.notificationNow().UTC())))
	err = observer.ReconcileLegacyNotification(checkCtx, goauth.LegacyNotificationReceipt{
		ID: claim.event.ID, TransportProtocol: claim.protocol, ValidUntil: claim.event.ValidUntil,
	})
	observationExpired := checkCtx.Err() != nil
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || observationExpired {
		return errLegacyProviderEvidenceUnavailable
	}
	return r.completeLegacyNotification(ctx, claim)
}

func (r *Runtime) completeLegacyNotification(ctx context.Context, claim notificationClaim) error {
	_, err := r.store.notificationExecer(ctx).ExecContext(ctx, `UPDATE auth_notification_deliveries
SET state='delivered', delivered_at=$3, ciphertext=NULL, nonce='\x'::bytea, additional_data='\x'::bytea,
 lease_token=NULL, leased_until=NULL, last_failure=NULL,
 last_sender_outcome=NULL,last_sender_code=NULL,last_sender_http_status=NULL,
 last_sender_attempt=NULL,last_sender_observed_at=NULL
WHERE id=$1 AND lease_token=$2 AND state='leased' AND transport_protocol=''
 AND gateway_receipt_id IS NULL AND leased_until>$3 AND valid_until>$3 AND delete_after>$3`,
		claim.event.ID, claim.leaseToken, r.notificationNow().UTC())
	return err
}
