package postgres

import (
	"context"
	"errors"
	"fmt"
)

// ExpireNotifications retires at most limit expired encrypted notification
// envelopes using the Runtime clock. It does not delete receipt rows, reset
// records, sessions, identifiers or audit events. Hosts may call it periodically;
// valid notifications and their original deadlines are never changed.
//
// Expired means no further attempts are allowed, not that a provider could never
// have accepted an in-flight request. The cleared lease prevents a late sender
// completion from overwriting expiry. Unknown transport outcomes remain the
// host's responsibility and must never be reported as confirmed non-delivery.
// limit must be in [1, 1000]. Locked rows are skipped for a later bounded pass.
// The verified database constraint valid_until <= delete_after makes this cutoff
// equivalent to either deadline expiring. A partial index supports batch location;
// hosts still need a timeout because locked-row skipping and contention cost time.
// A managed transaction on this database is joined; a foreign scope is rejected.
func (r *Runtime) ExpireNotifications(ctx context.Context, limit int) (int64, error) {
	if r == nil || r.store == nil || r.store.db == nil || r.notificationNow == nil {
		return 0, errors.New("PostgreSQL Runtime is not initialized")
	}
	if limit < 1 || limit > 1000 {
		return 0, errors.New("notification expiry limit must be 1..1000")
	}
	exec, err := r.SQLExecutor(ctx)
	if err != nil {
		return 0, err
	}
	result, err := exec.ExecContext(ctx, `
WITH expired AS (
 SELECT id FROM auth_notification_deliveries
 WHERE ciphertext IS NOT NULL AND valid_until <= $1
 ORDER BY valid_until, id
 FOR UPDATE SKIP LOCKED LIMIT $2
)
UPDATE auth_notification_deliveries n
SET state='expired', ciphertext=NULL, nonce='\x'::bytea, additional_data='\x'::bytea,
 lease_token=NULL, leased_until=NULL
FROM expired e WHERE n.id=e.id`, r.notificationNow().UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("expire managed notification batch: %w", err)
	}
	return result.RowsAffected()
}
