package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth"
)

// CreatePasswordResetForSubject is the explicit host-policy issuance capability.
// It never creates a credential or falls back to a primary-email lookup.
func (s *Store) CreatePasswordResetForSubject(ctx context.Context, record goauth.PasswordResetRecord) error {
	if record.SubjectID.IsZero() || record.Selector == "" || len(record.Digest.Digest) != 32 ||
		record.Digest.KeyID == "" || record.ExpectedNormalizedEmail != "" || record.ExpectedSecurityVersion < 1 ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) {
		return errors.New("invalid subject-bound password reset record")
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return fmt.Errorf("begin subject-bound password reset: %w", err)
	}
	defer rollbackWrite(tx, owned)
	var status string
	var version int64
	err = tx.QueryRowContext(ctx, `
SELECT status, security_version FROM auth_subjects
WHERE id = $1 AND retired_at IS NULL FOR UPDATE`, record.SubjectID).Scan(&status, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.ErrAccountNotFound
	}
	if err != nil {
		return fmt.Errorf("lock subject-bound password reset account: %w", err)
	}
	if status != string(goauth.SubjectStatusActive) || version != record.ExpectedSecurityVersion {
		return goauth.ErrAccountNotFound
	}
	var passwordPHC string
	err = tx.QueryRowContext(ctx, `
SELECT password_phc FROM auth_local_credentials WHERE subject_id = $1 FOR UPDATE`,
		record.SubjectID).Scan(&passwordPHC)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.ErrAccountNotFound
	}
	if err != nil {
		return fmt.Errorf("lock subject-bound password reset credential: %w", err)
	}
	if passwordPHC == "" {
		return goauth.ErrAccountNotFound
	}
	if err := replacePasswordReset(ctx, tx, record); err != nil {
		return err
	}
	return finishWrite(tx, owned)
}

// InvalidatePasswordResets retires outstanding reset records under the canonical
// subject lock. It joins the supplied managed transaction, so hosts can make an
// alias mutation and invalidation atomic. Returning an error must abort that
// transaction. Invalidation is required even when an old address is later restored.
func (r *Runtime) InvalidatePasswordResets(ctx context.Context, subjectID goauth.SubjectID) error {
	if r == nil || r.store == nil || r.notificationNow == nil {
		return errors.New("PostgreSQL Runtime is not initialized")
	}
	if subjectID.IsZero() {
		return goauth.ErrAccountNotFound
	}
	return r.store.InAuthTransaction(ctx, func(txCtx context.Context) error {
		if _, err := r.store.LockAccount(txCtx, subjectID); err != nil {
			return err
		}
		tx, err := r.store.notificationTx(txCtx)
		if err != nil {
			return err
		}
		return invalidatePasswordResets(txCtx, tx, subjectID, r.notificationNow().UTC())
	})
}

var _ goauth.PasswordResetSubjectStore = (*Store)(nil)
