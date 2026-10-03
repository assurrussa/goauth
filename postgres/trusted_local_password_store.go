package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth"
)

func (s *Store) SetTrustedLocalPassword(
	ctx context.Context, request goauth.TrustedLocalPasswordStoreRequest,
) (goauth.Account, error) {
	if request.SubjectID.IsZero() || request.ExpectedPasswordPHC == "" || request.NewPasswordPHC == "" ||
		request.ExpectedSecurityVersion < 1 || request.Now.IsZero() {
		return goauth.Account{}, errors.New("invalid trusted local password request")
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.Account{}, fmt.Errorf("begin trusted local password: %w", err)
	}
	defer rollbackWrite(tx, owned)

	var version int64
	err = tx.QueryRowContext(ctx, `SELECT security_version FROM auth_subjects WHERE id=$1 FOR UPDATE`,
		request.SubjectID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.Account{}, fmt.Errorf("lock trusted local password subject: %w", err)
	}
	var phc string
	var policy goauth.PasswordInputPolicy
	err = tx.QueryRowContext(ctx, `
SELECT password_phc,password_input_policy FROM auth_local_credentials WHERE subject_id=$1 FOR UPDATE`,
		request.SubjectID).Scan(&phc, &policy)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.Account{}, fmt.Errorf("lock trusted local credential: %w", err)
	}
	if version != request.ExpectedSecurityVersion {
		return goauth.Account{}, goauth.ErrSecurityVersionMismatch
	}
	if phc != request.ExpectedPasswordPHC || policy != request.ExpectedPasswordInputPolicy {
		return goauth.Account{}, goauth.ErrPasswordChangeConflict
	}
	updated, err := tx.ExecContext(ctx, `
UPDATE auth_local_credentials SET password_phc=$2,password_input_policy='unicode_v1',updated_at=$3
WHERE subject_id=$1 AND password_phc=$4 AND password_input_policy=$5`,
		request.SubjectID, request.NewPasswordPHC, request.Now, request.ExpectedPasswordPHC, request.ExpectedPasswordInputPolicy)
	if err != nil {
		return goauth.Account{}, fmt.Errorf("update trusted local credential: %w", err)
	}
	rows, err := updated.RowsAffected()
	if err != nil || rows != 1 {
		return goauth.Account{}, errors.New("trusted local password guard did not update exactly one row")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_subjects SET security_version=security_version+1,updated_at=$2 WHERE id=$1`,
		request.SubjectID, request.Now); err != nil {
		return goauth.Account{}, fmt.Errorf("increment trusted local password security version: %w", err)
	}
	if _, err := revokeSubjectSecurityState(ctx, tx, request.SubjectID, request.Now); err != nil {
		return goauth.Account{}, err
	}
	if err := invalidatePasswordResets(ctx, tx, request.SubjectID, request.Now); err != nil {
		return goauth.Account{}, err
	}
	account, err := getAccount(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.Account{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.Account{}, fmt.Errorf("commit trusted local password: %w", err)
	}
	return account, nil
}

var _ goauth.TrustedLocalPasswordStore = (*Store)(nil)
