package postgres

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goauth"
)

func (s *Store) IssueEmailChange(
	ctx context.Context,
	record goauth.EmailChangeRecord,
	limits goauth.EmailChallengeLimits,
) (goauth.EmailChangeIssueResult, error) {
	if record.ID == "" || record.SubjectID.IsZero() || record.NewDisplayValue == "" ||
		record.NewNormalizedValue == "" || len(record.Digest.Digest) != 32 ||
		len(record.RateDigest.Digest) != 32 || record.MaxAttempts <= 0 ||
		limits.MinResendInterval < 0 || limits.PerHour <= 0 || limits.PerDay <= 0 {
		return goauth.EmailChangeIssueResult{}, errors.New("invalid email change record or limits")
	}
	const action = "email_change"
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("begin email change issue: %w", err)
	}
	defer rollbackWrite(tx, owned)

	lockKey := record.RateDigest.KeyID + ":" + hex.EncodeToString(record.RateDigest.Digest) + ":" + action
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("lock email change rate limit: %w", err)
	}
	var currentNormalized string
	err = tx.QueryRowContext(ctx, `
SELECT normalized_value
FROM auth_identifiers
WHERE subject_id = $1 AND scheme = 'email' AND is_primary = true
FOR UPDATE`, record.SubjectID).Scan(&currentNormalized)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.EmailChangeIssueResult{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("lock primary email identifier: %w", err)
	}
	if currentNormalized == record.NewNormalizedValue {
		return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeSameValue}, nil
	}
	var (
		lastSend sql.NullTime
		lastHour int
		lastDay  int
	)
	if err := tx.QueryRowContext(ctx, `
SELECT
    max(occurred_at),
    count(*) FILTER (WHERE occurred_at >= $4),
    count(*) FILTER (WHERE occurred_at >= $5)
FROM auth_rate_limit_events
WHERE key_id = $1 AND bucket_digest = $2 AND action = $3`,
		record.RateDigest.KeyID,
		record.RateDigest.Digest,
		action,
		record.CreatedAt.Add(-time.Hour),
		record.CreatedAt.Add(-24*time.Hour),
	).Scan(&lastSend, &lastHour, &lastDay); err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("read email change rate limit: %w", err)
	}
	if lastSend.Valid && limits.MinResendInterval > 0 {
		retryAt := lastSend.Time.Add(limits.MinResendInterval)
		if record.CreatedAt.Before(retryAt) {
			return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeWait, RetryAt: retryAt}, nil
		}
	}
	if lastHour >= limits.PerHour {
		return goauth.EmailChangeIssueResult{
			Status:  goauth.EmailChangeHourlyLimit,
			RetryAt: record.CreatedAt.Add(time.Hour),
		}, nil
	}
	if lastDay >= limits.PerDay {
		return goauth.EmailChangeIssueResult{
			Status:  goauth.EmailChangeDailyLimit,
			RetryAt: record.CreatedAt.Add(24 * time.Hour),
		}, nil
	}
	var occupied bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM auth_identifiers
    WHERE scheme = 'email' AND normalized_value = $1 AND subject_id <> $2
)`, record.NewNormalizedValue, record.SubjectID).Scan(&occupied); err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("check email change uniqueness: %w", err)
	}
	if occupied {
		return goauth.EmailChangeIssueResult{}, goauth.ErrIdentifierAlreadyExists
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_email_change_records
SET consumed_at = $2
WHERE subject_id = $1 AND consumed_at IS NULL`, record.SubjectID, record.CreatedAt); err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("retire previous email changes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_rate_limit_events (subject_id, key_id, bucket_digest, action, occurred_at)
VALUES ($1, $2, $3, $4, $5)`,
		record.SubjectID,
		record.RateDigest.KeyID,
		record.RateDigest.Digest,
		action,
		record.CreatedAt,
	); err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("insert email change rate event: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_email_change_records (
    id, subject_id, new_display_value, new_normalized_value, key_id,
    code_digest, attempts, max_attempts, created_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, $9)`,
		record.ID,
		record.SubjectID,
		record.NewDisplayValue,
		record.NewNormalizedValue,
		record.Digest.KeyID,
		record.Digest.Digest,
		record.MaxAttempts,
		record.CreatedAt,
		record.ExpiresAt,
	); err != nil {
		return goauth.EmailChangeIssueResult{}, transformWriteError("insert email change", err)
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("commit email change issue: %w", err)
	}

	return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeIssued}, nil
}

func (s *Store) GetPendingEmailChange(
	ctx context.Context,
	subjectID goauth.SubjectID,
	now time.Time,
) (goauth.PendingEmailChange, error) {
	var pending goauth.PendingEmailChange
	err := s.db.QueryRowContext(ctx, `
SELECT id, subject_id, new_display_value, attempts, max_attempts, created_at, expires_at
FROM auth_email_change_records
WHERE subject_id = $1 AND consumed_at IS NULL AND expires_at > $2
ORDER BY created_at DESC, id DESC
LIMIT 1`, subjectID, now).Scan(
		&pending.ID,
		&pending.SubjectID,
		&pending.NewDisplayValue,
		&pending.Attempts,
		&pending.MaxAttempts,
		&pending.CreatedAt,
		&pending.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.PendingEmailChange{}, goauth.ErrEmailChangeNotFound
	}
	if err != nil {
		return goauth.PendingEmailChange{}, fmt.Errorf("get pending email change: %w", err)
	}

	return pending, nil
}

func (s *Store) VerifyEmailChange(
	ctx context.Context,
	request goauth.EmailChangeVerifyRequest,
) (goauth.EmailChangeVerifyResult, error) {
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("begin email change verification: %w", err)
	}
	defer rollbackWrite(tx, owned)

	var (
		id           string
		displayValue string
		normalized   string
		keyID        string
		storedDigest []byte
		attempts     int
		maxAttempts  int
		expiresAt    time.Time
	)
	err = tx.QueryRowContext(ctx, `
SELECT id, new_display_value, new_normalized_value, key_id, code_digest,
       attempts, max_attempts, expires_at
FROM auth_email_change_records
WHERE subject_id = $1 AND consumed_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT 1
FOR UPDATE`, request.SubjectID).Scan(
		&id,
		&displayValue,
		&normalized,
		&keyID,
		&storedDigest,
		&attempts,
		&maxAttempts,
		&expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.EmailChangeVerifyResult{Status: goauth.EmailChangeNotFound}, nil
	}
	if err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("lock email change record: %w", err)
	}
	if attempts >= maxAttempts {
		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeAttemptsUsed,
			Attempts: attempts,
		}, nil
	}
	if !request.Now.Before(expiresAt) {
		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeExpired,
			Attempts: attempts,
		}, nil
	}
	if !matchesEmailChangeDigest(keyID, storedDigest, request.Digests) {
		updated, err := tx.ExecContext(ctx, `
UPDATE auth_email_change_records
SET attempts = attempts + 1
WHERE id = $1 AND consumed_at IS NULL`, id)
		if err != nil {
			return goauth.EmailChangeVerifyResult{}, fmt.Errorf("increment email change attempts: %w", err)
		}
		rows, err := updated.RowsAffected()
		if err != nil || rows != 1 {
			return goauth.EmailChangeVerifyResult{}, errors.New("email change attempt guard did not update exactly one row")
		}
		if err := finishWrite(tx, owned); err != nil {
			return goauth.EmailChangeVerifyResult{}, fmt.Errorf("commit email change attempt: %w", err)
		}

		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeInvalid,
			Attempts: attempts + 1,
		}, nil
	}
	identifierUpdate, err := tx.ExecContext(ctx, `
UPDATE auth_identifiers
SET display_value = $2,
    normalized_value = $3,
    verified_at = $4,
    updated_at = $4
WHERE subject_id = $1 AND scheme = 'email' AND is_primary = true`,
		request.SubjectID,
		displayValue,
		normalized,
		request.Now,
	)
	if err != nil {
		return goauth.EmailChangeVerifyResult{}, transformWriteError("update primary email identifier", err)
	}
	rows, err := identifierUpdate.RowsAffected()
	if err != nil || rows != 1 {
		return goauth.EmailChangeVerifyResult{}, errors.New("email identifier guard did not update exactly one row")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_subjects
SET security_version = security_version + 1, updated_at = $2
WHERE id = $1`, request.SubjectID, request.Now); err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("increment email change security version: %w", err)
	}
	consumed, err := tx.ExecContext(ctx, `
UPDATE auth_email_change_records
SET consumed_at = $2
WHERE id = $1 AND consumed_at IS NULL`, id, request.Now)
	if err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("consume email change record: %w", err)
	}
	rows, err = consumed.RowsAffected()
	if err != nil || rows != 1 {
		return goauth.EmailChangeVerifyResult{}, errors.New("email change consume guard did not update exactly one row")
	}
	if _, err := revokeSubjectSecurityState(ctx, tx, request.SubjectID, request.Now); err != nil {
		return goauth.EmailChangeVerifyResult{}, err
	}
	if err := invalidatePasswordResets(ctx, tx, request.SubjectID, request.Now); err != nil {
		return goauth.EmailChangeVerifyResult{}, err
	}
	// A verification code issued for the former primary email must not remain
	// usable, even if its notification has not left the queue yet.
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_email_challenges
SET attempts = max_attempts
WHERE subject_id = $1 AND verified_at IS NULL AND attempts < max_attempts`, request.SubjectID); err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("invalidate previous email challenges: %w", err)
	}
	account, err := getAccount(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.EmailChangeVerifyResult{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("commit email change verification: %w", err)
	}

	return goauth.EmailChangeVerifyResult{
		Status:   goauth.EmailChangeVerified,
		Account:  account,
		Attempts: attempts,
	}, nil
}

func matchesEmailChangeDigest(keyID string, stored []byte, candidates []goauth.SecretDigest) bool {
	for _, candidate := range candidates {
		if candidate.KeyID == keyID && hmac.Equal(stored, candidate.Digest) {
			return true
		}
	}

	return false
}
