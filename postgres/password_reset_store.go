package postgres

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goauth"
)

func (s *Store) CreatePasswordReset(ctx context.Context, record goauth.PasswordResetRecord) error {
	if record.SubjectID.IsZero() || record.Selector == "" || len(record.Digest.Digest) != 32 {
		return errors.New("invalid password reset record")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin password reset issue: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_password_reset_records
SET consumed_at = $2
WHERE subject_id = $1 AND consumed_at IS NULL`, record.SubjectID, record.CreatedAt); err != nil {
		return fmt.Errorf("retire previous password resets: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_password_reset_records (
    selector, subject_id, key_id, secret_digest, created_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6)`,
		record.Selector,
		record.SubjectID,
		record.Digest.KeyID,
		record.Digest.Digest,
		record.CreatedAt,
		record.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert password reset: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit password reset issue: %w", err)
	}

	return nil
}

func (s *Store) ConsumePasswordReset(
	ctx context.Context,
	request goauth.PasswordResetConsumeRequest,
) (goauth.PasswordResetConsumeResult, error) {
	if request.Selector == "" || request.PasswordPHC == "" || len(request.Digest.Digest) != 32 {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("begin password reset consume: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var (
		subjectID  goauth.SubjectID
		keyID      string
		digest     []byte
		expiresAt  time.Time
		consumedAt sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
SELECT subject_id, key_id, secret_digest, expires_at, consumed_at
FROM auth_password_reset_records
WHERE selector = $1
FOR UPDATE`, request.Selector).Scan(&subjectID, &keyID, &digest, &expiresAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("lock password reset: %w", err)
	}
	if keyID != request.Digest.KeyID || !hmac.Equal(digest, request.Digest.Digest) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	if consumedAt.Valid {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetUsed}, nil
	}
	if !request.Now.Before(expiresAt) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetExpired}, nil
	}

	credentialUpdate, err := tx.ExecContext(ctx, `
UPDATE auth_local_credentials
SET password_phc = $2, updated_at = $3
WHERE subject_id = $1`, subjectID, request.PasswordPHC, request.Now)
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("update local credential: %w", err)
	}
	rows, err := credentialUpdate.RowsAffected()
	if err != nil || rows != 1 {
		return goauth.PasswordResetConsumeResult{}, errors.New("password reset credential guard did not update exactly one row")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_subjects
SET security_version = security_version + 1, updated_at = $2
WHERE id = $1`, subjectID, request.Now); err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("increment password security version: %w", err)
	}
	consume, err := tx.ExecContext(ctx, `
UPDATE auth_password_reset_records
SET consumed_at = $2
WHERE selector = $1 AND consumed_at IS NULL`, request.Selector, request.Now)
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("consume password reset record: %w", err)
	}
	rows, err = consume.RowsAffected()
	if err != nil || rows != 1 {
		return goauth.PasswordResetConsumeResult{}, errors.New("password reset consume guard did not update exactly one row")
	}
	if _, err := revokeSubjectSecurityState(ctx, tx, subjectID, request.Now); err != nil {
		return goauth.PasswordResetConsumeResult{}, err
	}
	account, err := getAccount(ctx, tx, subjectID)
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("commit password reset consume: %w", err)
	}

	return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetConsumed, Account: account}, nil
}
