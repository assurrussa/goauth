package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/assurrussa/goauth"
)

func (s *Store) TakeRateLimit(
	ctx context.Context,
	request goauth.RateLimitRequest,
) (goauth.RateLimitResult, error) {
	request.Action = strings.TrimSpace(request.Action)
	if request.Action == "" || request.Limit <= 0 || request.Window <= 0 ||
		request.Bucket.KeyID == "" || len(request.Bucket.Digest) != 32 || request.Now.IsZero() {
		return goauth.RateLimitResult{}, errors.New("invalid rate limit request")
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
	var (
		count  int
		oldest sql.NullTime
	)
	if err := tx.QueryRowContext(ctx, `
SELECT count(*), min(occurred_at)
FROM auth_rate_limit_events
WHERE key_id = $1
  AND bucket_digest = $2
  AND action = $3
  AND occurred_at >= $4`,
		request.Bucket.KeyID,
		request.Bucket.Digest,
		request.Action,
		request.Now.Add(-request.Window),
	).Scan(&count, &oldest); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("read rate limit bucket: %w", err)
	}
	if count >= request.Limit {
		retryAt := request.Now.Add(request.Window)
		if oldest.Valid {
			retryAt = oldest.Time.Add(request.Window)
		}
		return goauth.RateLimitResult{RetryAt: retryAt}, nil
	}
	var subjectID any
	if !request.SubjectID.IsZero() {
		subjectID = request.SubjectID
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_rate_limit_events (subject_id, key_id, bucket_digest, action, occurred_at)
VALUES ($1, $2, $3, $4, $5)`,
		subjectID,
		request.Bucket.KeyID,
		request.Bucket.Digest,
		request.Action,
		request.Now,
	); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("record rate limit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("commit rate limit event: %w", err)
	}

	return goauth.RateLimitResult{Allowed: true}, nil
}
