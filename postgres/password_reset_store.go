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
	if record.SubjectID.IsZero() || record.Selector == "" || len(record.Digest.Digest) != 32 ||
		record.ExpectedNormalizedEmail == "" || record.ExpectedSecurityVersion < 1 {
		return errors.New("invalid password reset record")
	}

	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return fmt.Errorf("begin password reset issue: %w", err)
	}
	defer rollbackWrite(tx, owned)
	var status, normalizedEmail string
	var securityVersion int64
	err = tx.QueryRowContext(ctx, `
SELECT s.status, s.security_version, i.normalized_value
FROM auth_subjects s
JOIN auth_identifiers i ON i.subject_id = s.id
  AND i.scheme = 'email' AND i.is_primary
WHERE s.id = $1
FOR UPDATE OF s`, record.SubjectID).Scan(&status, &securityVersion, &normalizedEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.ErrAccountNotFound
	}
	if err != nil {
		return fmt.Errorf("guard password reset account: %w", err)
	}
	if status != string(goauth.SubjectStatusActive) ||
		securityVersion != record.ExpectedSecurityVersion ||
		normalizedEmail != record.ExpectedNormalizedEmail {
		return goauth.ErrAccountNotFound
	}
	if err := replacePasswordReset(ctx, tx, record); err != nil {
		return err
	}
	if err := finishWrite(tx, owned); err != nil {
		return fmt.Errorf("commit password reset issue: %w", err)
	}

	return nil
}

func (s *Store) ConsumePasswordReset(
	ctx context.Context,
	request goauth.PasswordResetConsumeRequest,
) (goauth.PasswordResetConsumeResult, error) {
	return s.consumePasswordReset(ctx, request, nil)
}

// ConsumePasswordResetWithPreparation authenticates and locks the current token
// before preparing a replacement credential. prepare must not mutate state.
func (s *Store) ConsumePasswordResetWithPreparation(
	ctx context.Context, request goauth.PasswordResetConsumeRequest,
	prepare func(context.Context, goauth.Account) (string, error),
) (goauth.PasswordResetConsumeResult, error) {
	if prepare == nil {
		return goauth.PasswordResetConsumeResult{}, errors.New("password reset preparation is required")
	}
	started := time.Now()
	var result goauth.PasswordResetConsumeResult
	err := s.InAuthTransaction(ctx, func(txCtx context.Context) error {
		// Include transaction-start wait without counting it twice later.
		request.Now = securityTime(txCtx, request.Now, started)
		var err error
		result, err = s.consumePasswordReset(txCtx, request, prepare)
		return err
	})
	return result, err
}

func (s *Store) consumePasswordReset(
	ctx context.Context, request goauth.PasswordResetConsumeRequest,
	prepare func(context.Context, goauth.Account) (string, error),
) (goauth.PasswordResetConsumeResult, error) {
	started := time.Now()
	origin := request.Now
	if request.Selector == "" || (request.PasswordPHC == "" && prepare == nil) || len(request.Digest.Digest) != 32 {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}

	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("begin password reset consume: %w", err)
	}
	defer rollbackWrite(tx, owned)

	var (
		lookupID   goauth.SubjectID
		lookupKey  string
		lookupHash []byte
		status     string
		subjectID  goauth.SubjectID
		keyID      string
		digest     []byte
		expiresAt  time.Time
		consumedAt sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
SELECT subject_id, key_id, secret_digest FROM auth_password_reset_records WHERE selector = $1`,
		request.Selector).Scan(&lookupID, &lookupKey, &lookupHash)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("lookup password reset subject: %w", err)
	}
	if lookupKey != request.Digest.KeyID || !hmac.Equal(lookupHash, request.Digest.Digest) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	err = tx.QueryRowContext(ctx, `SELECT status FROM auth_subjects WHERE id = $1 FOR UPDATE`, lookupID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("lock password reset subject: %w", err)
	}
	if status != string(goauth.SubjectStatusActive) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
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
	if subjectID != lookupID || keyID != request.Digest.KeyID || !hmac.Equal(digest, request.Digest.Digest) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	if consumedAt.Valid {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetUsed}, nil
	}
	// The token must still be valid after both subject and reset locks were acquired.
	request.Now = securityTime(ctx, origin, started)
	if !request.Now.Before(expiresAt) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetExpired}, nil
	}

	if prepare != nil {
		var currentPHC string
		err := tx.QueryRowContext(ctx, `
SELECT password_phc FROM auth_local_credentials WHERE subject_id = $1 FOR UPDATE`, subjectID).Scan(&currentPHC)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && currentPHC == "") {
			return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
		}
		if err != nil {
			return goauth.PasswordResetConsumeResult{}, fmt.Errorf("lock password reset credential: %w", err)
		}
		account, err := getAccount(ctx, tx, subjectID)
		if err != nil {
			return goauth.PasswordResetConsumeResult{}, err
		}
		request.PasswordPHC, err = prepare(ctx, account)
		if err != nil {
			return goauth.PasswordResetConsumeResult{}, err
		}
		if err := ctx.Err(); err != nil {
			return goauth.PasswordResetConsumeResult{}, err
		}
		if request.PasswordPHC == "" {
			return goauth.PasswordResetConsumeResult{}, goauth.ErrInvalidPassword
		}
		// Always start from the original supplied clock origin; do not add the
		// elapsed lock/hash time twice for direct store consumers.
		request.Now = securityTime(ctx, origin, started)
		if !request.Now.Before(expiresAt) {
			return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetExpired}, nil
		}
	}

	credentialUpdate, err := tx.ExecContext(ctx, `
UPDATE auth_local_credentials
SET password_phc = $2, updated_at = $3, password_input_policy = 'unicode_v1'
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
	if err := invalidatePasswordResets(ctx, tx, subjectID, request.Now); err != nil {
		return goauth.PasswordResetConsumeResult{}, err
	}
	account, err := getAccount(ctx, tx, subjectID)
	if err != nil {
		return goauth.PasswordResetConsumeResult{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.PasswordResetConsumeResult{}, fmt.Errorf("commit password reset consume: %w", err)
	}

	return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetConsumed, Account: account}, nil
}

func invalidatePasswordResets(ctx context.Context, tx *sql.Tx, subjectID goauth.SubjectID, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_password_reset_records
SET consumed_at = $2
WHERE subject_id = $1 AND consumed_at IS NULL`, subjectID, now); err != nil {
		return fmt.Errorf("invalidate password resets: %w", err)
	}
	return nil
}

func replacePasswordReset(ctx context.Context, tx *sql.Tx, record goauth.PasswordResetRecord) error {
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
	return nil
}
