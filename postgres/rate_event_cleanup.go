package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RateLimitCleanupRequest describes one bounded, independent retention pass.
// Before is exclusive; zero defaults to the configured Runtime clock minus 25h.
// An explicit Before must be at least 24h old. Limit must be in [1, 1000].
// Callers must retain the longest window used by EVERY consumer of the shared
// table, plus clock-skew/request-latency margin. The 24h minimum only covers
// Runtime policy bounds; direct Store.TakeRateLimit permits longer windows.
type RateLimitCleanupRequest struct {
	Before time.Time
	Limit  int
}

// CleanupRateLimitEvents deletes only expired rate events, returning a count
// only after its own transaction commits. Active same-handle and foreign managed
// transaction contexts are rejected before SQL. Errors return zero; an uncertain
// commit preserves goauth.ErrOperationOutcomeUnknown. Retrying may delete another
// expired batch and does not recover the original count.
//
// At most Limit oldest eligible candidates are materialized before row locking.
// Locked candidates are skipped without walking farther through the backlog.
// Fewer deletions, including zero, never prove that the backlog is empty. This
// method performs no internal retry/loop and takes no advisory or subject locks.
// Hosts must use deadlines and bounded, spaced worker wakes: bounded candidate
// cardinality and the retention index cannot guarantee wall-clock latency.
func (r *Runtime) CleanupRateLimitEvents(ctx context.Context, request RateLimitCleanupRequest) (int64, error) {
	if r == nil || r.db == nil || r.store == nil || r.notificationNow == nil {
		return 0, errors.New("PostgreSQL Runtime is not initialized")
	}
	if request.Limit < 1 || request.Limit > 1000 {
		return 0, errors.New("rate event cleanup limit must be 1..1000")
	}
	now := r.notificationNow().UTC()
	if now.IsZero() {
		return 0, errors.New("rate event cleanup clock must not be zero")
	}
	if request.Before.IsZero() {
		request.Before = now.Add(-25 * time.Hour)
	} else if request.Before.After(now.Add(-24 * time.Hour)) {
		return 0, errors.New("rate event cleanup cutoff must be at least 24h old")
	}
	existing, err := r.store.notificationTx(ctx)
	if err != nil {
		return 0, err
	}
	if existing != nil {
		return 0, errors.New("rate event cleanup requires an independent transaction")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin rate event cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, rateEventCleanupSQL, request.Before.UTC(), request.Limit)
	if err != nil {
		return 0, fmt.Errorf("delete rate event batch: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read rate event cleanup count: %w", err)
	}
	if err := commitAuthTransaction(tx); err != nil {
		return 0, fmt.Errorf("commit rate event cleanup: %w", err)
	}
	return count, nil
}

// The locking lateral subquery keeps each row-lock lookup inside the bounded
// candidate set, even if the planner would otherwise favor scanning the table.
// Recheck the cutoff when locking in case an external writer moved a timestamp.
// Delete by the locked tuple locator to avoid a hash join scanning the entire
// target table; the row lock keeps that locator stable through this statement.
const rateEventCleanupSQL = `
WITH candidates AS MATERIALIZED (
 SELECT id FROM auth_rate_limit_events
 WHERE occurred_at < $1
 ORDER BY occurred_at, id LIMIT $2
), locked AS MATERIALIZED (
 SELECT row.ctid FROM candidates c
 CROSS JOIN LATERAL (
  SELECT e.ctid FROM auth_rate_limit_events e
  WHERE e.id = c.id AND e.occurred_at < $1
  FOR UPDATE OF e SKIP LOCKED
 ) row
)
DELETE FROM auth_rate_limit_events e
WHERE e.ctid = ANY (ARRAY(SELECT ctid FROM locked))`
