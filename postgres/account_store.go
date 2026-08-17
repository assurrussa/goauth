package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/assurrussa/goauth"
)

const accountColumns = `
s.id,
s.status,
s.security_version,
s.created_at,
s.updated_at,
i.id,
i.scheme,
i.display_value,
i.normalized_value,
i.verified_at,
i.created_at,
i.updated_at,
p.username,
p.display_name,
p.given_name,
p.family_name`

const accountFrom = `
FROM auth_subjects s
JOIN auth_identifiers i
  ON i.subject_id = s.id
 AND i.scheme = 'email'
 AND i.is_primary = true
JOIN auth_basic_profiles p ON p.subject_id = s.id`

func (s *Store) CreateLocalAccount(
	ctx context.Context,
	record goauth.LocalAccountRecord,
) (goauth.Account, error) {
	if record.Account.Subject.IsZero() || record.Account.PrimaryEmail.ID == "" || record.PasswordPHC == "" {
		return goauth.Account{}, errors.New("invalid local account record")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return goauth.Account{}, fmt.Errorf("begin local account transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	account := record.Account
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_subjects (id, status, security_version, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)`,
		account.Subject.ID,
		account.Subject.Status,
		account.Subject.SecurityVersion,
		account.Subject.CreatedAt,
		account.Subject.UpdatedAt,
	); err != nil {
		return goauth.Account{}, transformWriteError("insert auth subject", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_identifiers (
    id, subject_id, scheme, display_value, normalized_value,
    is_primary, verified_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, true, $6, $7, $8)`,
		account.PrimaryEmail.ID,
		account.Subject.ID,
		account.PrimaryEmail.Scheme,
		account.PrimaryEmail.DisplayValue,
		account.PrimaryEmail.NormalizedValue,
		account.PrimaryEmail.VerifiedAt,
		account.PrimaryEmail.CreatedAt,
		account.PrimaryEmail.UpdatedAt,
	); err != nil {
		return goauth.Account{}, transformWriteError("insert auth identifier", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_basic_profiles (
    subject_id, username, display_name, given_name, family_name, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		account.Subject.ID,
		account.Profile.Username,
		account.Profile.DisplayName,
		account.Profile.GivenName,
		account.Profile.FamilyName,
		account.Subject.CreatedAt,
		account.Subject.UpdatedAt,
	); err != nil {
		return goauth.Account{}, transformWriteError("insert basic profile", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_local_credentials (subject_id, password_phc, created_at, updated_at)
VALUES ($1, $2, $3, $4)`,
		account.Subject.ID,
		record.PasswordPHC,
		account.Subject.CreatedAt,
		account.Subject.UpdatedAt,
	); err != nil {
		return goauth.Account{}, transformWriteError("insert local credential", err)
	}
	if err := tx.Commit(); err != nil {
		return goauth.Account{}, fmt.Errorf("commit local account transaction: %w", err)
	}

	return account, nil
}

func (s *Store) FindLocalAccount(
	ctx context.Context,
	identifier goauth.IdentifierInput,
) (goauth.LocalAccountRecord, error) {
	query := `SELECT ` + accountColumns + `, c.password_phc ` + accountFrom + `
JOIN auth_local_credentials c ON c.subject_id = s.id
WHERE i.scheme = $1 AND i.normalized_value = $2
LIMIT 1`
	row := s.db.QueryRowContext(ctx, query, identifier.Scheme, strings.TrimSpace(identifier.Value))
	account, passwordPHC, err := scanLocalAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.LocalAccountRecord{}, fmt.Errorf("find local account: %w", err)
	}

	return goauth.LocalAccountRecord{Account: account, PasswordPHC: passwordPHC}, nil
}

func (s *Store) GetLocalAccount(
	ctx context.Context,
	subjectID goauth.SubjectID,
) (goauth.LocalAccountRecord, error) {
	query := `SELECT ` + accountColumns + `, c.password_phc ` + accountFrom + `
JOIN auth_local_credentials c ON c.subject_id = s.id
WHERE s.id = $1
LIMIT 1`
	account, passwordPHC, err := scanLocalAccount(s.db.QueryRowContext(ctx, query, subjectID))
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.LocalAccountRecord{}, fmt.Errorf("get local account: %w", err)
	}

	return goauth.LocalAccountRecord{Account: account, PasswordPHC: passwordPHC}, nil
}

func (s *Store) FindAccount(
	ctx context.Context,
	identifier goauth.IdentifierInput,
) (goauth.Account, error) {
	query := `SELECT ` + accountColumns + ` ` + accountFrom + `
WHERE i.scheme = $1 AND i.normalized_value = $2
LIMIT 1`
	account, err := scanAccount(s.db.QueryRowContext(
		ctx,
		query,
		identifier.Scheme,
		strings.TrimSpace(identifier.Value),
	))
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.Account{}, fmt.Errorf("find account: %w", err)
	}

	return account, nil
}

func (s *Store) GetAccount(ctx context.Context, subjectID goauth.SubjectID) (goauth.Account, error) {
	return getAccount(ctx, s.db, subjectID)
}

func (s *Store) UpdateBasicProfile(
	ctx context.Context,
	subjectID goauth.SubjectID,
	profile goauth.BasicProfile,
	now time.Time,
) (goauth.Account, error) {
	updated, err := s.db.ExecContext(ctx, `
UPDATE auth_basic_profiles
SET username = $2,
    display_name = $3,
    given_name = $4,
    family_name = $5,
    updated_at = $6
WHERE subject_id = $1`,
		subjectID,
		profile.Username,
		profile.DisplayName,
		profile.GivenName,
		profile.FamilyName,
		now,
	)
	if err != nil {
		return goauth.Account{}, fmt.Errorf("update basic profile: %w", err)
	}
	rows, err := updated.RowsAffected()
	if err != nil {
		return goauth.Account{}, fmt.Errorf("read basic profile update count: %w", err)
	}
	if rows != 1 {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}

	return getAccount(ctx, s.db, subjectID)
}

func (s *Store) ChangePassword(
	ctx context.Context,
	request goauth.PasswordChangeStoreRequest,
) (goauth.PasswordChangeStoreResult, error) {
	if request.SubjectID.IsZero() || request.ExpectedPasswordPHC == "" || request.NewPasswordPHC == "" ||
		request.Now.IsZero() {
		return goauth.PasswordChangeStoreResult{}, errors.New("invalid password change request")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("begin password change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var currentPHC, status string
	err = tx.QueryRowContext(ctx, `
SELECT c.password_phc, s.status
FROM auth_local_credentials c
JOIN auth_subjects s ON s.id = c.subject_id
WHERE c.subject_id = $1
FOR UPDATE OF c, s`, request.SubjectID).Scan(&currentPHC, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreMissing}, nil
	}
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("lock local credential: %w", err)
	}
	if currentPHC != request.ExpectedPasswordPHC {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreConflict}, nil
	}
	if goauth.SubjectStatus(status) != goauth.SubjectStatusActive {
		return goauth.PasswordChangeStoreResult{}, goauth.ErrAccountUnavailable
	}
	updated, err := tx.ExecContext(ctx, `
UPDATE auth_local_credentials
SET password_phc = $2, updated_at = $3
WHERE subject_id = $1 AND password_phc = $4`,
		request.SubjectID,
		request.NewPasswordPHC,
		request.Now,
		request.ExpectedPasswordPHC,
	)
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("update local credential: %w", err)
	}
	rows, err := updated.RowsAffected()
	if err != nil || rows != 1 {
		return goauth.PasswordChangeStoreResult{}, errors.New("password change guard did not update exactly one row")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_subjects
SET security_version = security_version + 1, updated_at = $2
WHERE id = $1`, request.SubjectID, request.Now); err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("increment password security version: %w", err)
	}
	if _, err := revokeSubjectSecurityState(ctx, tx, request.SubjectID, request.Now); err != nil {
		return goauth.PasswordChangeStoreResult{}, err
	}
	account, err := getAccount(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("commit password change: %w", err)
	}

	return goauth.PasswordChangeStoreResult{
		Status:  goauth.PasswordChangeStoreSucceeded,
		Account: account,
	}, nil
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func getAccount(ctx context.Context, db queryRower, subjectID goauth.SubjectID) (goauth.Account, error) {
	query := `SELECT ` + accountColumns + ` ` + accountFrom + ` WHERE s.id = $1 LIMIT 1`
	account, err := scanAccount(db.QueryRowContext(ctx, query, subjectID))
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.Account{}, fmt.Errorf("get account: %w", err)
	}

	return account, nil
}

type scanner interface {
	Scan(destinations ...any) error
}

func scanAccount(row scanner) (goauth.Account, error) {
	var account goauth.Account
	var status string
	var scheme string
	var verifiedAt sql.NullTime
	err := row.Scan(
		&account.Subject.ID,
		&status,
		&account.Subject.SecurityVersion,
		&account.Subject.CreatedAt,
		&account.Subject.UpdatedAt,
		&account.PrimaryEmail.ID,
		&scheme,
		&account.PrimaryEmail.DisplayValue,
		&account.PrimaryEmail.NormalizedValue,
		&verifiedAt,
		&account.PrimaryEmail.CreatedAt,
		&account.PrimaryEmail.UpdatedAt,
		&account.Profile.Username,
		&account.Profile.DisplayName,
		&account.Profile.GivenName,
		&account.Profile.FamilyName,
	)
	if err != nil {
		return goauth.Account{}, err
	}
	account.Subject.Status = goauth.SubjectStatus(status)
	account.PrimaryEmail.SubjectID = account.Subject.ID
	account.PrimaryEmail.Scheme = goauth.IdentifierScheme(scheme)
	if verifiedAt.Valid {
		value := verifiedAt.Time
		account.PrimaryEmail.VerifiedAt = &value
	}

	return account, nil
}

func scanLocalAccount(row scanner) (goauth.Account, string, error) {
	var account goauth.Account
	var status string
	var scheme string
	var verifiedAt sql.NullTime
	var passwordPHC string
	err := row.Scan(
		&account.Subject.ID,
		&status,
		&account.Subject.SecurityVersion,
		&account.Subject.CreatedAt,
		&account.Subject.UpdatedAt,
		&account.PrimaryEmail.ID,
		&scheme,
		&account.PrimaryEmail.DisplayValue,
		&account.PrimaryEmail.NormalizedValue,
		&verifiedAt,
		&account.PrimaryEmail.CreatedAt,
		&account.PrimaryEmail.UpdatedAt,
		&account.Profile.Username,
		&account.Profile.DisplayName,
		&account.Profile.GivenName,
		&account.Profile.FamilyName,
		&passwordPHC,
	)
	if err != nil {
		return goauth.Account{}, "", err
	}
	account.Subject.Status = goauth.SubjectStatus(status)
	account.PrimaryEmail.SubjectID = account.Subject.ID
	account.PrimaryEmail.Scheme = goauth.IdentifierScheme(scheme)
	if verifiedAt.Valid {
		value := verifiedAt.Time
		account.PrimaryEmail.VerifiedAt = &value
	}

	return account, passwordPHC, nil
}

func transformWriteError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%s: %w", operation, goauth.ErrIdentifierAlreadyExists)
	}

	return fmt.Errorf("%s: %w", operation, err)
}
