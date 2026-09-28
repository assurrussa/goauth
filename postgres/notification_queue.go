package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth"
)

type notificationClaim struct {
	event      goauth.EncryptedEvent
	leaseToken string
	attempts   int
}

const (
	notificationPending   = "pending"
	notificationBlocked   = "blocked"
	notificationLeased    = "leased"
	notificationDelivered = "delivered"
	notificationExhausted = "exhausted"
	notificationExpired   = "expired"
)

func (s *Store) EnqueueEncrypted(ctx context.Context, event goauth.EncryptedEvent) error {
	if event.ID == "" || event.Type == "" || event.SubjectID.IsZero() ||
		event.ValidUntil.IsZero() || event.Envelope.DeleteAfter.Before(event.ValidUntil) ||
		event.Envelope.KeyID == "" || len(event.Envelope.Nonce) == 0 ||
		len(event.Envelope.Ciphertext) == 0 || len(event.Envelope.AdditionalData) == 0 {
		return errors.New("invalid managed encrypted notification")
	}
	if _, err := s.notificationExecer(ctx).ExecContext(ctx, `
INSERT INTO auth_notification_deliveries (
    id, subject_id, event_type, reference_id, valid_until, key_id, nonce,
    ciphertext, additional_data, created_at, delete_after, next_attempt_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $10)`,
		event.ID, event.SubjectID, event.Type, event.ReferenceID, event.ValidUntil,
		event.Envelope.KeyID, event.Envelope.Nonce, event.Envelope.Ciphertext,
		event.Envelope.AdditionalData, event.Envelope.CreatedAt, event.Envelope.DeleteAfter,
	); err != nil {
		return fmt.Errorf("enqueue managed notification: %w", err)
	}
	return nil
}

// DeleteEncrypted cannot acknowledge a managed delivery without a lease token.
// Only the worker's token-checked completion path can clear ciphertext.
func (s *Store) DeleteEncrypted(context.Context, string) error {
	return errors.New("managed notifications can only be acknowledged by the lease-owning worker")
}

func (s *Store) DeleteExpiredEncrypted(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.notificationExecer(ctx).ExecContext(ctx, `
UPDATE auth_notification_deliveries
SET state = 'expired', ciphertext = NULL, nonce = '\x'::bytea,
    additional_data = '\x'::bytea, lease_token = NULL, leased_until = NULL
WHERE ciphertext IS NOT NULL AND (valid_until <= $1 OR delete_after <= $1)`, before)
	if err != nil {
		return 0, fmt.Errorf("expire managed notifications: %w", err)
	}
	return result.RowsAffected()
}

func (s *Store) claimNotification(ctx context.Context, now time.Time, lease time.Duration) (notificationClaim, error) {
	leaseToken := uuid.NewString()
	var claim notificationClaim
	var envelope goauth.EncryptedEnvelope
	err := s.db.QueryRowContext(ctx, `
UPDATE auth_notification_deliveries
SET state = 'leased', lease_token = $2, leased_until = $3
WHERE id = (
    SELECT id FROM auth_notification_deliveries
    WHERE ciphertext IS NOT NULL AND valid_until > $1 AND delete_after > $1
      AND ((state IN ('pending', 'blocked') AND next_attempt_at <= $1)
        OR (state = 'leased' AND leased_until <= $1))
    ORDER BY next_attempt_at, created_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id, subject_id, event_type, reference_id, valid_until,
          key_id, nonce, ciphertext, additional_data, created_at, delete_after, attempts`,
		now, leaseToken, now.Add(lease),
	).Scan(
		&claim.event.ID, &claim.event.SubjectID, &claim.event.Type,
		&claim.event.ReferenceID, &claim.event.ValidUntil,
		&envelope.KeyID, &envelope.Nonce, &envelope.Ciphertext,
		&envelope.AdditionalData, &envelope.CreatedAt, &envelope.DeleteAfter,
		&claim.attempts,
	)
	if err != nil {
		return notificationClaim{}, err
	}
	claim.event.Envelope = envelope
	claim.leaseToken = leaseToken
	return claim, nil
}

func (s *Store) notificationCurrent(ctx context.Context, event goauth.EncryptedEvent, now time.Time) (bool, error) {
	if !now.Before(event.ValidUntil) {
		return false, nil
	}
	var current bool
	switch event.Type {
	case "password_reset":
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM auth_password_reset_records
    WHERE selector = $1 AND subject_id = $2 AND consumed_at IS NULL AND expires_at > $3
)`, event.ReferenceID, event.SubjectID, now).Scan(&current)
		return current, err
	case "email_challenge":
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM auth_email_challenges c
    JOIN auth_identifiers i ON i.id = c.identifier_id AND i.subject_id = c.subject_id
    JOIN auth_subjects s ON s.id = c.subject_id
    WHERE c.id = $1 AND c.subject_id = $2 AND c.verified_at IS NULL
      AND c.expires_at > $3 AND c.attempts < c.max_attempts
      AND s.status = 'active' AND i.scheme = 'email' AND i.is_primary = true
      AND i.updated_at <= c.created_at
      AND c.id = (SELECT latest.id FROM auth_email_challenges latest
        WHERE latest.subject_id = c.subject_id AND latest.purpose = c.purpose
        ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1)
)`, event.ReferenceID, event.SubjectID, now).Scan(&current)
		return current, err
	case "email_change":
		err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
    SELECT 1 FROM auth_email_change_records c
    JOIN auth_subjects s ON s.id = c.subject_id
    WHERE c.id = $1 AND c.subject_id = $2 AND c.consumed_at IS NULL
      AND c.expires_at > $3 AND c.attempts < c.max_attempts
      AND s.status = 'active'
      AND c.id = (SELECT latest.id FROM auth_email_change_records latest
        WHERE latest.subject_id = c.subject_id
        ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1)
)`, event.ReferenceID, event.SubjectID, now).Scan(&current)
		return current, err
	default:
		return true, nil
	}
}

// reserveNotificationSend counts a possible external call before it begins.
// A lease takeover or exhausted budget cannot reserve another call.
func (s *Store) reserveNotificationSend(ctx context.Context, claim notificationClaim, maxAttempts int) (bool, error) {
	result, err := s.db.ExecContext(ctx, `
UPDATE auth_notification_deliveries
SET attempts = attempts + 1
WHERE id = $1 AND lease_token = $2 AND state = 'leased' AND attempts < $3`,
		claim.event.ID, claim.leaseToken, maxAttempts)
	if err != nil {
		return false, fmt.Errorf("reserve managed notification send: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check managed notification send reservation: %w", err)
	}
	return rows == 1, nil
}

func (s *Store) finishNotification(ctx context.Context, claim notificationClaim, state, failure string, next time.Time) error {
	_, err := s.finishNotificationResult(ctx, claim, state, failure, next)
	return err
}

func (s *Store) finishNotificationResult(
	ctx context.Context,
	claim notificationClaim,
	state, failure string,
	next time.Time,
) (bool, error) {
	if state != notificationPending && state != notificationBlocked && state != notificationExhausted &&
		state != notificationExpired && state != notificationDelivered {
		return false, errors.New("invalid notification finish state")
	}
	var deliveredAt any
	if state == notificationDelivered {
		deliveredAt = time.Now().UTC()
	}
	var nextAttempt any
	if !next.IsZero() {
		nextAttempt = next
	}
	clearPayload := state == notificationDelivered || state == notificationExhausted || state == notificationExpired
	result, err := s.db.ExecContext(ctx, `
UPDATE auth_notification_deliveries
SET state = $3,
    next_attempt_at = COALESCE($4, next_attempt_at),
    last_failure = NULLIF($5, ''), delivered_at = $6,
    ciphertext = CASE WHEN $7 THEN NULL ELSE ciphertext END,
    nonce = CASE WHEN $7 THEN '\x'::bytea ELSE nonce END,
    additional_data = CASE WHEN $7 THEN '\x'::bytea ELSE additional_data END,
    lease_token = NULL, leased_until = NULL
WHERE id = $1 AND lease_token = $2 AND state = 'leased'`,
		claim.event.ID, claim.leaseToken, state, nextAttempt, failure, deliveredAt, clearPayload)
	if err != nil {
		return false, fmt.Errorf("finish managed notification: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check managed notification completion: %w", err)
	}
	// Cleanup may expire an in-flight notification, or another worker may
	// reclaim an elapsed lease. Neither case lets this worker change the row.
	if rows == 0 {
		return false, nil
	}
	if rows != 1 {
		return false, errors.New("managed notification completion updated multiple rows")
	}
	return true, nil
}

func (s *Store) notificationCounts(ctx context.Context) (NotificationQueueStats, error) {
	var stats NotificationQueueStats
	rows, err := s.db.QueryContext(ctx, `
SELECT state, count(*) FROM auth_notification_deliveries GROUP BY state`)
	if err != nil {
		return stats, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int64
		if err := rows.Scan(&state, &count); err != nil {
			return stats, err
		}
		switch state {
		case notificationPending:
			stats.Pending = count
		case notificationLeased:
			stats.Leased = count
		case notificationBlocked:
			stats.Blocked = count
		case notificationDelivered:
			stats.Delivered = count
		case notificationExhausted:
			stats.Exhausted = count
		case notificationExpired:
			stats.Expired = count
		}
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}
	var oldest sql.NullTime
	if err := s.db.QueryRowContext(ctx, `
SELECT min(created_at) FROM auth_notification_deliveries
WHERE state IN ('pending', 'blocked', 'leased')`).Scan(&oldest); err != nil {
		return stats, err
	}
	if oldest.Valid {
		stats.OldestQueuedAt = &oldest.Time
	}
	return stats, nil
}

var (
	_ goauth.EncryptedEventSink      = (*Store)(nil)
	_ goauth.NotificationTransaction = (*Store)(nil)
)
