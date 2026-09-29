package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/assurrussa/goauth"
)

// TakeRateLimit commits admission independently of subsequent auth writes.
// Joining an outer transaction would lose attempts on rollback; opening another
// connection while it holds locks can deadlock. Reject that composition instead.
func (s *Store) TakeRateLimit(
	ctx context.Context,
	request goauth.RateLimitRequest,
) (goauth.RateLimitResult, error) {
	request.Action = strings.TrimSpace(request.Action)
	if request.Action == "" || request.Limit <= 0 || request.Window <= 0 ||
		request.Bucket.KeyID == "" || len(request.Bucket.Digest) != 32 || request.Now.IsZero() {
		return goauth.RateLimitResult{}, errors.New("invalid rate limit request")
	}
	existing, err := s.notificationTx(ctx)
	if err != nil {
		return goauth.RateLimitResult{}, err
	}
	if existing != nil {
		return goauth.RateLimitResult{}, goauth.ErrRateLimitTransactionUnsupported
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("begin rate limit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	lockKey := request.Bucket.KeyID + ":" + hex.EncodeToString(request.Bucket.Digest) + ":" + request.Action
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("lock rate limit bucket: %w", err)
	}
	// The limit-th newest event is the last one that must leave the inclusive
	// window, even if the configured limit was reduced. Do not load the full
	// history or deduplicate timestamps: distinct attempts may share a timestamp.
	var limiting time.Time
	err = tx.QueryRowContext(ctx, `
SELECT occurred_at
FROM auth_rate_limit_events
WHERE key_id = $1 AND bucket_digest = $2 AND action = $3 AND occurred_at >= $4
ORDER BY occurred_at DESC
OFFSET $5 LIMIT 1`,
		request.Bucket.KeyID, request.Bucket.Digest, request.Action,
		request.Now.Add(-request.Window), request.Limit-1,
	).Scan(&limiting)
	if err == nil {
		return goauth.RateLimitResult{RetryAt: limiting.Add(request.Window)}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return goauth.RateLimitResult{}, fmt.Errorf("read rate limit bucket: %w", err)
	}

	var subjectID any
	if !request.SubjectID.IsZero() {
		subjectID = request.SubjectID
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_rate_limit_events (subject_id, key_id, bucket_digest, action, occurred_at)
VALUES ($1, $2, $3, $4, $5)`,
		subjectID, request.Bucket.KeyID, request.Bucket.Digest, request.Action, request.Now,
	); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("record rate limit event: %w", err)
	}
	if err := commitAuthTransaction(tx); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("commit rate limit event: %w", err)
	}
	return goauth.RateLimitResult{Allowed: true}, nil
}
