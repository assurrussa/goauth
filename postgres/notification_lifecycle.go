package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CancelNotification stops future managed sends for a pending or blocked
// delivery whose original deadlines and retry budget remain live. It never
// cancels a leased delivery, including an elapsed lease with an unknown outcome.
// It clears the encrypted payload and lease ownership, retaining the receipt,
// attempt count and original deadlines. A false, nil result changes no row.
//
// Cancellation does not prove that an earlier attempt was not accepted by the
// provider. It does not revoke a credential or reissue a notification. Eligibility
// is based on queue state and deadlines, not the current credential reference.
// A managed transaction on this database is joined, allowing host audit writes
// to commit atomically; the result is provisional until that transaction commits.
func (r *Runtime) CancelNotification(ctx context.Context, id string) (bool, error) {
	if r == nil || r.store == nil || r.store.db == nil || r.notificationNow == nil ||
		r.notificationWorker.MaxAttempts < 1 {
		return false, errors.New("PostgreSQL Runtime is not initialized")
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil {
		return false, errors.New("notification delivery ID must be a nonzero UUID")
	}
	now := r.notificationNow().UTC()
	if now.IsZero() {
		return false, errors.New("notification clock must not be zero")
	}
	var changed bool
	err = r.InAuthTransaction(ctx, func(txCtx context.Context) error {
		exec, execErr := r.SQLExecutor(txCtx)
		if execErr != nil {
			return execErr
		}
		result, execErr := exec.ExecContext(txCtx, notificationCancellationSQL,
			parsed.String(), now, r.notificationWorker.MaxAttempts)
		if execErr != nil {
			return execErr
		}
		count, countErr := result.RowsAffected()
		if countErr != nil {
			return countErr
		}
		if count < 0 || count > 1 {
			return errors.New("notification cancellation returned an invalid row count")
		}
		changed = count == 1
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("cancel managed notification: %w", err)
	}
	return changed, nil
}

const notificationCancellationSQL = `
UPDATE auth_notification_deliveries
SET state='cancelled', last_failure='operator_cancelled', ciphertext=NULL, nonce='\x'::bytea, additional_data='\x'::bytea,
 lease_token=NULL, leased_until=NULL
WHERE id=$1 AND state IN ('pending', 'blocked') AND ciphertext IS NOT NULL
 AND lease_token IS NULL AND leased_until IS NULL
 AND valid_until > $2 AND delete_after > $2 AND attempts < $3`

// CleanupNotificationReceipts deletes at most limit scrubbed terminal managed
// notification receipts. It does not expire payloads or touch other auth data.
// Retention defaults to seven days and must be at least 24 hours. Both the
// original validity deadline and any delivered_at timestamp must be strictly
// older than the retention cutoff. In-flight, nonterminal and unsanitized rows
// remain, including rows whose leases have elapsed.
//
// limit must be in [1, 1000]. Locked rows are skipped; a zero result does not
// prove that no eligible rows remain. Hosts own timeouts and spaced scheduling;
// a row bound does not bound query cost or elapsed time. A managed transaction
// on this database is joined, and the count is provisional until it commits.
func (r *Runtime) CleanupNotificationReceipts(
	ctx context.Context, retention time.Duration, limit int,
) (int64, error) {
	if r == nil || r.store == nil || r.store.db == nil || r.notificationNow == nil {
		return 0, errors.New("PostgreSQL Runtime is not initialized")
	}
	if limit < 1 || limit > 1000 {
		return 0, errors.New("notification receipt cleanup limit must be 1..1000")
	}
	if retention == 0 {
		retention = 7 * 24 * time.Hour
	}
	if retention < 24*time.Hour {
		return 0, errors.New("notification receipt retention must be at least 24 hours")
	}
	now := r.notificationNow().UTC()
	if now.IsZero() {
		return 0, errors.New("notification clock must not be zero")
	}
	var count int64
	err := r.InAuthTransaction(ctx, func(txCtx context.Context) error {
		exec, execErr := r.SQLExecutor(txCtx)
		if execErr != nil {
			return execErr
		}
		result, execErr := exec.ExecContext(txCtx, notificationReceiptCleanupSQL, now.Add(-retention), limit)
		if execErr != nil {
			return execErr
		}
		count, execErr = result.RowsAffected()
		if execErr != nil {
			return execErr
		}
		if count < 0 || count > int64(limit) {
			return errors.New("notification receipt cleanup returned an invalid row count")
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("clean managed notification receipts: %w", err)
	}
	return count, nil
}

const notificationReceiptCleanupSQL = `
DELETE FROM auth_notification_deliveries WHERE id IN (
 SELECT id FROM auth_notification_deliveries
 WHERE state IN ('delivered', 'exhausted', 'expired', 'cancelled')
  AND ciphertext IS NULL AND octet_length(nonce)=0 AND octet_length(additional_data)=0
  AND lease_token IS NULL AND leased_until IS NULL
  AND GREATEST(COALESCE(delivered_at, valid_until), valid_until) < $1
 ORDER BY GREATEST(COALESCE(delivered_at, valid_until), valid_until), id
 LIMIT $2 FOR UPDATE SKIP LOCKED)`
