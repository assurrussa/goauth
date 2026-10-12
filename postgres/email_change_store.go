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
	if record.Scope != "" {
		return goauth.EmailChangeIssueResult{}, goauth.ErrEmailChangeScopeUnavailable
	}
	return s.issueEmailChange(ctx, record, limits)
}

func (s *Store) IssueScopedEmailChange(
	ctx context.Context, record goauth.EmailChangeRecord, limits goauth.EmailChallengeLimits,
) (goauth.EmailChangeIssueResult, error) {
	if record.Scope == "" || record.ExpectedSecurityVersion <= 0 || record.TargetSnapshot.Version <= 0 {
		return goauth.EmailChangeIssueResult{}, goauth.ErrEmailChangeScopeUnavailable
	}
	return s.issueEmailChange(ctx, record, limits)
}

func (s *Store) issueEmailChange(
	ctx context.Context, record goauth.EmailChangeRecord, limits goauth.EmailChallengeLimits,
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
	if err := lockActiveSubject(ctx, tx, record.SubjectID); err != nil {
		return goauth.EmailChangeIssueResult{}, err
	}

	lockKey := record.RateDigest.KeyID + ":" + hex.EncodeToString(record.RateDigest.Digest) + ":" + action
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return goauth.EmailChangeIssueResult{}, fmt.Errorf("lock email change rate limit: %w", err)
	}
	if err := emailChangeIssueTarget(ctx, tx, record); err != nil {
		if errors.Is(err, goauth.ErrEmailChangeSameValue) {
			return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeSameValue}, nil
		}
		return goauth.EmailChangeIssueResult{}, err
	}
	quota, err := readEmailQuota(ctx, tx, record.RateDigest, action, record.CreatedAt, limits)
	if err != nil {
		return goauth.EmailChangeIssueResult{}, err
	}
	if quota.waiting {
		return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeWait, RetryAt: quota.retryAt}, nil
	}
	if quota.hourly {
		return goauth.EmailChangeIssueResult{
			Status:  goauth.EmailChangeHourlyLimit,
			RetryAt: quota.retryAt,
		}, nil
	}
	if quota.daily {
		return goauth.EmailChangeIssueResult{
			Status:  goauth.EmailChangeDailyLimit,
			RetryAt: quota.retryAt,
		}, nil
	}
	if record.Scope == "" {
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
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_email_change_records
SET consumed_at = $2
WHERE subject_id = $1 AND scope = $3 AND consumed_at IS NULL`, record.SubjectID, record.CreatedAt, record.Scope); err != nil {
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
    code_digest, attempts, max_attempts, created_at, expires_at,
    scope, expected_security_version, target_version, old_normalized_value
)
VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, $9, $10, NULLIF($11::bigint, 0), NULLIF($12::bigint, 0),
    CASE WHEN $10 = '' THEN NULL ELSE $13 END)`,
		record.ID,
		record.SubjectID,
		record.NewDisplayValue,
		record.NewNormalizedValue,
		record.Digest.KeyID,
		record.Digest.Digest,
		record.MaxAttempts,
		record.CreatedAt,
		record.ExpiresAt,
		record.Scope, record.ExpectedSecurityVersion, record.TargetSnapshot.Version, record.TargetSnapshot.NormalizedEmail,
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
	return s.pendingEmailChange(ctx, subjectID, "", now)
}

func (s *Store) GetPendingScopedEmailChange(
	ctx context.Context, subjectID goauth.SubjectID, scope goauth.EmailChangeScope, now time.Time,
) (goauth.PendingEmailChange, error) {
	if scope == "" {
		return goauth.PendingEmailChange{}, goauth.ErrEmailChangeScopeUnavailable
	}
	return s.pendingEmailChange(ctx, subjectID, scope, now)
}

func (s *Store) pendingEmailChange(
	ctx context.Context, subjectID goauth.SubjectID, scope goauth.EmailChangeScope, now time.Time,
) (goauth.PendingEmailChange, error) {
	var pending goauth.PendingEmailChange
	err := s.queryer(ctx).QueryRowContext(ctx, `
SELECT id, subject_id, new_display_value, attempts, max_attempts, created_at, expires_at,
 scope, COALESCE(expected_security_version, 0), COALESCE(target_version, 0), COALESCE(old_normalized_value, ''),
 CASE WHEN scope = '' THEN '' ELSE new_normalized_value END
FROM auth_email_change_records
WHERE subject_id = $1 AND consumed_at IS NULL AND expires_at > $2 AND scope = $3
ORDER BY created_at DESC, id DESC
LIMIT 1`, subjectID, now, scope).Scan(
		&pending.ID,
		&pending.SubjectID,
		&pending.NewDisplayValue,
		&pending.Attempts,
		&pending.MaxAttempts,
		&pending.CreatedAt,
		&pending.ExpiresAt,
		&pending.Scope, &pending.ExpectedSecurityVersion, &pending.TargetSnapshot.Version,
		&pending.TargetSnapshot.NormalizedEmail, &pending.NewNormalizedValue,
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
	if request.Scope != "" {
		return goauth.EmailChangeVerifyResult{}, goauth.ErrEmailChangeScopeUnavailable
	}
	return s.verifyEmailChange(ctx, request)
}

func (s *Store) VerifyScopedEmailChange(
	ctx context.Context, request goauth.EmailChangeVerifyRequest,
) (goauth.EmailChangeVerifyResult, error) {
	if request.Scope == "" || request.RecordID == "" || request.ExpectedSecurityVersion <= 0 {
		return goauth.EmailChangeVerifyResult{}, goauth.ErrEmailChangeScopeUnavailable
	}
	return s.verifyEmailChange(ctx, request)
}

func (s *Store) verifyEmailChange(
	ctx context.Context, request goauth.EmailChangeVerifyRequest,
) (goauth.EmailChangeVerifyResult, error) {
	started := time.Now()
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("begin email change verification: %w", err)
	}
	defer rollbackWrite(tx, owned)
	if err := lockActiveSubject(ctx, tx, request.SubjectID); err != nil {
		return goauth.EmailChangeVerifyResult{}, err
	}

	var (
		id              string
		displayValue    string
		normalized      string
		keyID           string
		storedDigest    []byte
		attempts        int
		maxAttempts     int
		expiresAt       time.Time
		expectedVersion int64
	)
	err = tx.QueryRowContext(ctx, `
SELECT id, new_display_value, new_normalized_value, key_id, code_digest,
       attempts, max_attempts, expires_at, COALESCE(expected_security_version, 0)
FROM auth_email_change_records
WHERE subject_id = $1 AND consumed_at IS NULL AND scope = $2
ORDER BY created_at DESC, id DESC
LIMIT 1
FOR UPDATE`, request.SubjectID, request.Scope).Scan(
		&id,
		&displayValue,
		&normalized,
		&keyID,
		&storedDigest,
		&attempts,
		&maxAttempts,
		&expiresAt, &expectedVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.EmailChangeVerifyResult{Status: goauth.EmailChangeNotFound}, nil
	}
	if err != nil {
		return goauth.EmailChangeVerifyResult{}, fmt.Errorf("lock email change record: %w", err)
	}
	if request.Scope != "" {
		if id != request.RecordID || expectedVersion != request.ExpectedSecurityVersion {
			return goauth.EmailChangeVerifyResult{}, goauth.ErrSecurityVersionMismatch
		}
		if err := emailChangeExpectedVersion(ctx, tx, request.SubjectID, expectedVersion); err != nil {
			return goauth.EmailChangeVerifyResult{}, err
		}
	}
	if attempts >= maxAttempts {
		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeAttemptsUsed,
			Attempts: attempts,
		}, nil
	}
	request.Now = securityTime(ctx, request.Now, started)
	if !request.Now.Before(expiresAt) {
		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeExpired,
			Attempts: attempts,
		}, nil
	}
	if !matchesEmailChangeDigest(keyID, storedDigest, request.Digests) {
		return recordEmailChangeAttempt(ctx, tx, owned, id, attempts)
	}
	if request.Scope == "" {
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
	rows, err := consumed.RowsAffected()
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

func recordEmailChangeAttempt(
	ctx context.Context, tx *sql.Tx, owned bool, id string, attempts int,
) (goauth.EmailChangeVerifyResult, error) {
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

func matchesEmailChangeDigest(keyID string, stored []byte, candidates []goauth.SecretDigest) bool {
	for _, candidate := range candidates {
		if candidate.KeyID == keyID && hmac.Equal(stored, candidate.Digest) {
			return true
		}
	}

	return false
}

func emailChangeIssueTarget(ctx context.Context, tx *sql.Tx, record goauth.EmailChangeRecord) error {
	if record.Scope != "" {
		if record.TargetSnapshot.NormalizedEmail == record.NewNormalizedValue {
			return goauth.ErrEmailChangeSameValue
		}
		return emailChangeExpectedVersion(ctx, tx, record.SubjectID, record.ExpectedSecurityVersion)
	}
	var current string
	err := tx.QueryRowContext(ctx, `
SELECT normalized_value FROM auth_identifiers
WHERE subject_id = $1 AND scheme = 'email' AND is_primary = true FOR UPDATE`, record.SubjectID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.ErrAccountNotFound
	}
	if err != nil {
		return fmt.Errorf("lock primary email identifier: %w", err)
	}
	if current == record.NewNormalizedValue {
		return goauth.ErrEmailChangeSameValue
	}
	return nil
}

func emailChangeExpectedVersion(ctx context.Context, tx *sql.Tx, subject goauth.SubjectID, expected int64) error {
	var current int64
	if err := tx.QueryRowContext(ctx,
		`SELECT security_version FROM auth_subjects WHERE id = $1`, subject).Scan(&current); err != nil {
		return err
	}
	if current != expected {
		return goauth.ErrSecurityVersionMismatch
	}
	return nil
}
