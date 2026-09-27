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

func (s *Store) IssueEmailChallenge(
	ctx context.Context,
	record goauth.EmailChallengeRecord,
	limits goauth.EmailChallengeLimits,
) (goauth.EmailChallengeIssueResult, error) {
	if record.ID == "" || record.SubjectID.IsZero() || record.IdentifierID == "" ||
		len(record.Digest.Digest) != 32 || len(record.RateDigest.Digest) != 32 || record.MaxAttempts <= 0 ||
		limits.MinResendInterval < 0 || limits.PerHour <= 0 || limits.PerDay <= 0 {
		return goauth.EmailChallengeIssueResult{}, errors.New("invalid email challenge record or limits")
	}
	action := "email_challenge:" + string(record.Purpose)
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.EmailChallengeIssueResult{}, fmt.Errorf("begin email challenge issue: %w", err)
	}
	defer rollbackWrite(tx, owned)

	lockKey := record.RateDigest.KeyID + ":" + hex.EncodeToString(record.RateDigest.Digest) + ":" + action
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return goauth.EmailChallengeIssueResult{}, fmt.Errorf("lock email challenge rate limit: %w", err)
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
		return goauth.EmailChallengeIssueResult{}, fmt.Errorf("read email challenge rate limit: %w", err)
	}
	if lastSend.Valid && limits.MinResendInterval > 0 {
		retryAt := lastSend.Time.Add(limits.MinResendInterval)
		if record.CreatedAt.Before(retryAt) {
			return goauth.EmailChallengeIssueResult{Status: goauth.EmailChallengeWait, RetryAt: retryAt}, nil
		}
	}
	if lastHour >= limits.PerHour {
		return goauth.EmailChallengeIssueResult{
			Status:  goauth.EmailChallengeHourlyLimit,
			RetryAt: record.CreatedAt.Add(time.Hour),
		}, nil
	}
	if lastDay >= limits.PerDay {
		return goauth.EmailChallengeIssueResult{
			Status:  goauth.EmailChallengeDailyLimit,
			RetryAt: record.CreatedAt.Add(24 * time.Hour),
		}, nil
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
		return goauth.EmailChallengeIssueResult{}, fmt.Errorf("insert email challenge rate event: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_email_challenges (
    id, subject_id, identifier_id, purpose, key_id, code_digest,
    attempts, max_attempts, created_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, $9)`,
		record.ID,
		record.SubjectID,
		record.IdentifierID,
		record.Purpose,
		record.Digest.KeyID,
		record.Digest.Digest,
		record.MaxAttempts,
		record.CreatedAt,
		record.ExpiresAt,
	); err != nil {
		return goauth.EmailChallengeIssueResult{}, fmt.Errorf("insert email challenge: %w", err)
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.EmailChallengeIssueResult{}, fmt.Errorf("commit email challenge issue: %w", err)
	}

	return goauth.EmailChallengeIssueResult{Status: goauth.EmailChallengeIssued}, nil
}

func (s *Store) VerifyEmailChallenge(
	ctx context.Context,
	request goauth.EmailChallengeVerifyRequest,
) (goauth.EmailChallengeVerifyResult, error) {
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("begin email challenge verify: %w", err)
	}
	defer rollbackWrite(tx, owned)

	var (
		challengeID  string
		identifierID string
		storedKeyID  string
		storedDigest []byte
		attempts     int
		maxAttempts  int
		expiresAt    time.Time
		verifiedAt   sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
SELECT id, identifier_id, key_id, code_digest, attempts, max_attempts, expires_at, verified_at
FROM auth_email_challenges
WHERE subject_id = $1 AND purpose = $2
ORDER BY created_at DESC, id DESC
LIMIT 1
FOR UPDATE`, request.SubjectID, request.Purpose).Scan(
		&challengeID,
		&identifierID,
		&storedKeyID,
		&storedDigest,
		&attempts,
		&maxAttempts,
		&expiresAt,
		&verifiedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.EmailChallengeVerifyResult{Status: goauth.EmailChallengeInvalid}, nil
	}
	if err != nil {
		return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("lock email challenge: %w", err)
	}
	if verifiedAt.Valid {
		account, err := getAccount(ctx, tx, request.SubjectID)
		if err != nil {
			return goauth.EmailChallengeVerifyResult{}, err
		}
		return goauth.EmailChallengeVerifyResult{
			Status:   goauth.EmailChallengeAlreadyVerified,
			Account:  account,
			Attempts: attempts,
		}, nil
	}
	if attempts >= maxAttempts {
		return goauth.EmailChallengeVerifyResult{
			Status:   goauth.EmailChallengeAttemptsUsed,
			Attempts: attempts,
		}, nil
	}
	if !request.Now.Before(expiresAt) {
		return goauth.EmailChallengeVerifyResult{
			Status:   goauth.EmailChallengeExpired,
			Attempts: attempts,
		}, nil
	}
	if !matchesDigest(storedKeyID, storedDigest, request.Digests) {
		update, err := tx.ExecContext(ctx, `
UPDATE auth_email_challenges
SET attempts = attempts + 1
WHERE id = $1 AND verified_at IS NULL`, challengeID)
		if err != nil {
			return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("increment email challenge attempts: %w", err)
		}
		rows, err := update.RowsAffected()
		if err != nil || rows != 1 {
			return goauth.EmailChallengeVerifyResult{}, errors.New("email challenge attempt guard did not update exactly one row")
		}
		if err := finishWrite(tx, owned); err != nil {
			return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("commit email challenge attempt: %w", err)
		}
		return goauth.EmailChallengeVerifyResult{
			Status:   goauth.EmailChallengeInvalid,
			Attempts: attempts + 1,
		}, nil
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_email_challenges SET verified_at = $2 WHERE id = $1`, challengeID, request.Now); err != nil {
		return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("mark email challenge verified: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_identifiers
SET verified_at = COALESCE(verified_at, $2), updated_at = $2
WHERE id = $1 AND subject_id = $3`, identifierID, request.Now, request.SubjectID); err != nil {
		return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("mark email identifier verified: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_sessions
SET scope = $2
WHERE subject_id = $1
  AND realm = $3
  AND scope = $4
  AND revoked_at IS NULL`,
		request.SubjectID,
		goauth.SessionScopeAuthenticated,
		goauth.RealmUser,
		goauth.SessionScopeConfirmation,
	); err != nil {
		return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("promote verified user sessions: %w", err)
	}
	account, err := getAccount(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.EmailChallengeVerifyResult{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.EmailChallengeVerifyResult{}, fmt.Errorf("commit email challenge verification: %w", err)
	}

	return goauth.EmailChallengeVerifyResult{
		Status:   goauth.EmailChallengeVerified,
		Account:  account,
		Attempts: attempts,
	}, nil
}

func matchesDigest(keyID string, stored []byte, candidates []goauth.SecretDigest) bool {
	for _, candidate := range candidates {
		if candidate.KeyID == keyID && hmac.Equal(stored, candidate.Digest) {
			return true
		}
	}

	return false
}
