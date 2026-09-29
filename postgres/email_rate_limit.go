package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/assurrussa/goauth"
)

type emailQuota struct {
	waiting bool
	hourly  bool
	daily   bool
	retryAt time.Time
}

func (q *emailQuota) addRetry(at time.Time) {
	if at.After(q.retryAt) {
		q.retryAt = at
	}
}

func readEmailQuota(
	ctx context.Context,
	tx *sql.Tx,
	digest goauth.SecretDigest,
	action string,
	now time.Time,
	limits goauth.EmailChallengeLimits,
) (emailQuota, error) {
	var lastSend sql.NullTime
	var hourly, daily int
	err := tx.QueryRowContext(ctx, `
SELECT
    max(occurred_at),
    count(*) FILTER (WHERE occurred_at >= $4),
    count(*) FILTER (WHERE occurred_at >= $5)
FROM auth_rate_limit_events
WHERE key_id = $1 AND bucket_digest = $2 AND action = $3`,
		digest.KeyID, digest.Digest, action, now.Add(-time.Hour), now.Add(-24*time.Hour),
	).Scan(&lastSend, &hourly, &daily)
	if err != nil {
		return emailQuota{}, fmt.Errorf("read email rate limit: %w", err)
	}

	var result emailQuota
	if lastSend.Valid && limits.MinResendInterval > 0 {
		retryAt := lastSend.Time.Add(limits.MinResendInterval)
		if now.Before(retryAt) {
			result.waiting = true
			result.addRetry(retryAt)
		}
	}
	if hourly >= limits.PerHour {
		limiting, err := limitingEmailRateEvent(ctx, tx, digest, action, now.Add(-time.Hour), limits.PerHour-1)
		if err != nil {
			return emailQuota{}, fmt.Errorf("read hourly email rate limit: %w", err)
		}
		result.hourly = true
		result.addRetry(limiting.Add(time.Hour))
	}
	if daily >= limits.PerDay {
		limiting, err := limitingEmailRateEvent(ctx, tx, digest, action, now.Add(-24*time.Hour), limits.PerDay-1)
		if err != nil {
			return emailQuota{}, fmt.Errorf("read daily email rate limit: %w", err)
		}
		result.daily = true
		result.addRetry(limiting.Add(24 * time.Hour))
	}
	return result, nil
}

// The limit-th newest active event is the last event that must expire before
// another issue is admissible, including when a host lowers its configured limit.
func limitingEmailRateEvent(
	ctx context.Context,
	tx *sql.Tx,
	digest goauth.SecretDigest,
	action string,
	cutoff time.Time,
	offset int,
) (time.Time, error) {
	var occurredAt time.Time
	err := tx.QueryRowContext(ctx, `
SELECT occurred_at FROM auth_rate_limit_events
WHERE key_id = $1 AND bucket_digest = $2 AND action = $3 AND occurred_at >= $4
ORDER BY occurred_at DESC
OFFSET $5 LIMIT 1`, digest.KeyID, digest.Digest, action, cutoff, offset).Scan(&occurredAt)
	if err != nil {
		return time.Time{}, err
	}
	return occurredAt, nil
}
