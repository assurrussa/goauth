package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

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

	lockKey := request.Bucket.KeyID + ":" + hex.EncodeToString(request.Bucket.Digest) + ":" + request.Action

	existingTx, err := s.notificationTx(ctx)
	if err != nil {
		return goauth.RateLimitResult{}, err
	}

	// When called inside an existing managed auth transaction, join the active
	// transaction to eliminate connection pool starvation (including MaxOpenConns == 1)
	// and avoid lock deadlocks. Record an in-memory attempt fallback so that caller
	// rollback does not discard attempt accounting.
	if existingTx != nil {
		return s.takeRateLimitInTx(ctx, existingTx, lockKey, request)
	}

	return s.takeRateLimitAutonomous(ctx, lockKey, request)
}

func (s *Store) takeRateLimitAutonomous(
	ctx context.Context,
	lockKey string,
	request goauth.RateLimitRequest,
) (goauth.RateLimitResult, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("begin rate limit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("lock rate limit bucket: %w", err)
	}

	cutoff := request.Now.Add(-request.Window)
	dbEvents, err := readRateEvents(ctx, tx, request.Bucket.KeyID, request.Bucket.Digest, request.Action, cutoff)
	if err != nil {
		return goauth.RateLimitResult{}, err
	}

	active := s.mergeActiveEvents(dbEvents, lockKey, cutoff)
	if len(active) >= request.Limit {
		sort.Slice(active, func(i, j int) bool { return active[i].After(active[j]) })
		return goauth.RateLimitResult{RetryAt: active[request.Limit-1].Add(request.Window)}, nil
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

func (s *Store) takeRateLimitInTx(
	ctx context.Context,
	tx *sql.Tx,
	lockKey string,
	request goauth.RateLimitRequest,
) (goauth.RateLimitResult, error) {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return goauth.RateLimitResult{}, fmt.Errorf("lock rate limit bucket: %w", err)
	}

	cutoff := request.Now.Add(-request.Window)
	dbEvents, err := readRateEvents(ctx, tx, request.Bucket.KeyID, request.Bucket.Digest, request.Action, cutoff)
	if err != nil {
		return goauth.RateLimitResult{}, err
	}

	active := s.mergeActiveEvents(dbEvents, lockKey, cutoff)
	if len(active) >= request.Limit {
		sort.Slice(active, func(i, j int) bool { return active[i].After(active[j]) })
		return goauth.RateLimitResult{RetryAt: active[request.Limit-1].Add(request.Window)}, nil
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

	s.recordMemoryEvent(lockKey, request.Now)

	return goauth.RateLimitResult{Allowed: true}, nil
}

func (s *Store) mergeActiveEvents(
	dbEvents []time.Time,
	lockKey string,
	cutoff time.Time,
) []time.Time {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	active := append([]time.Time(nil), dbEvents...)
	seen := make(map[time.Time]struct{}, len(active))
	for _, at := range active {
		seen[at] = struct{}{}
	}

	mem := s.rateEvents[lockKey]
	filteredMem := make([]time.Time, 0, len(mem))
	for _, at := range mem {
		if !at.Before(cutoff) {
			filteredMem = append(filteredMem, at)
			if _, ok := seen[at]; !ok {
				active = append(active, at)
				seen[at] = struct{}{}
			}
		}
	}
	s.rateEvents[lockKey] = filteredMem
	return active
}

func (s *Store) recordMemoryEvent(lockKey string, at time.Time) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	s.rateEvents[lockKey] = append(s.rateEvents[lockKey], at)
}

func readRateEvents(
	ctx context.Context,
	tx *sql.Tx,
	keyID string,
	digest []byte,
	action string,
	cutoff time.Time,
) ([]time.Time, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT occurred_at
FROM auth_rate_limit_events
WHERE key_id = $1
  AND bucket_digest = $2
  AND action = $3
  AND occurred_at >= $4
ORDER BY occurred_at DESC`,
		keyID,
		digest,
		action,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("read rate limit bucket: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []time.Time
	for rows.Next() {
		var at time.Time
		if err := rows.Scan(&at); err != nil {
			return nil, fmt.Errorf("scan rate limit event: %w", err)
		}
		events = append(events, at)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rate limit events: %w", err)
	}
	return events, nil
}
