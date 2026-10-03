package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
LEFT JOIN auth_identifiers i
  ON i.subject_id = s.id
 AND i.scheme = 'email'
 AND i.is_primary = true
JOIN auth_basic_profiles p ON p.subject_id = s.id`

func (s *Store) CreateLocalAccount(
	ctx context.Context,
	record goauth.LocalAccountRecord,
) (goauth.Account, error) {
	return s.createLocalAccount(ctx, record, record.Account.PrimaryEmail)
}

func (s *Store) CreateLocalIdentity(ctx context.Context, record goauth.LocalIdentityRecord) (goauth.Account, error) {
	if record.Identifier.SubjectID != record.Account.Subject.ID || record.Identifier.Scheme == "" ||
		record.Identifier.Scheme == goauth.IdentifierSchemeEmail || record.Account.PrimaryEmail.ID != "" {
		return goauth.Account{}, errors.New("invalid local identity record")
	}
	return s.createLocalAccount(ctx, record.LocalAccountRecord, record.Identifier)
}

func (s *Store) createLocalAccount(
	ctx context.Context, record goauth.LocalAccountRecord, identifier goauth.Identifier,
) (goauth.Account, error) {
	if record.Account.Subject.IsZero() || identifier.ID == "" || record.PasswordPHC == "" {
		return goauth.Account{}, errors.New("invalid local account record")
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.Account{}, fmt.Errorf("begin local account transaction: %w", err)
	}
	defer rollbackWrite(tx, owned)

	account := record.Account
	if record.PasswordInputPolicy == "" {
		record.PasswordInputPolicy = goauth.PasswordInputPolicyUnicode
	}
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
		identifier.ID,
		account.Subject.ID,
		identifier.Scheme,
		identifier.DisplayValue,
		identifier.NormalizedValue,
		identifier.VerifiedAt,
		identifier.CreatedAt,
		identifier.UpdatedAt,
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
INSERT INTO auth_local_credentials (subject_id, password_phc, created_at, updated_at, password_input_policy)
VALUES ($1, $2, $3, $4, $5)`,
		account.Subject.ID,
		record.PasswordPHC,
		account.Subject.CreatedAt,
		account.Subject.UpdatedAt,
		record.PasswordInputPolicy,
	); err != nil {
		return goauth.Account{}, transformWriteError("insert local credential", err)
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.Account{}, fmt.Errorf("commit local account transaction: %w", err)
	}

	return account, nil
}

func (s *Store) FindLocalAccount(
	ctx context.Context,
	identifier goauth.IdentifierInput,
) (goauth.LocalAccountRecord, error) {
	query := `SELECT ` + accountColumns + `, c.password_phc, c.password_input_policy ` + accountFrom + `
JOIN auth_local_credentials c ON c.subject_id = s.id
JOIN auth_identifiers lookup ON lookup.subject_id = s.id AND lookup.is_primary = true
WHERE lookup.scheme = $1 AND lookup.normalized_value = $2
LIMIT 1`
	row := s.queryer(ctx).QueryRowContext(ctx, query, identifier.Scheme, identifier.Value)
	record, err := scanLocalAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.LocalAccountRecord{}, fmt.Errorf("find local account: %w", err)
	}

	return record, nil
}

func (s *Store) GetLocalAccount(
	ctx context.Context,
	subjectID goauth.SubjectID,
) (goauth.LocalAccountRecord, error) {
	query := `SELECT ` + accountColumns + `, c.password_phc, c.password_input_policy ` + accountFrom + `
JOIN auth_local_credentials c ON c.subject_id = s.id
WHERE s.id = $1
LIMIT 1`
	record, err := scanLocalAccount(s.queryer(ctx).QueryRowContext(ctx, query, subjectID))
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.LocalAccountRecord{}, fmt.Errorf("get local account: %w", err)
	}

	return record, nil
}

func (s *Store) FindAccount(
	ctx context.Context,
	identifier goauth.IdentifierInput,
) (goauth.Account, error) {
	query := `SELECT ` + accountColumns + ` ` + accountFrom + `
JOIN auth_identifiers lookup ON lookup.subject_id = s.id AND lookup.is_primary = true
WHERE lookup.scheme = $1 AND lookup.normalized_value = $2
LIMIT 1`
	account, err := scanAccount(s.queryer(ctx).QueryRowContext(
		ctx,
		query,
		identifier.Scheme,
		identifier.Value,
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
	return getAccount(ctx, s.queryer(ctx), subjectID)
}

func (s *Store) UpdateBasicProfile(
	ctx context.Context,
	subjectID goauth.SubjectID,
	profile goauth.BasicProfile,
	now time.Time,
) (goauth.Account, error) {
	updated, err := s.notificationExecer(ctx).ExecContext(ctx, `
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

	return getAccount(ctx, s.queryer(ctx), subjectID)
}

func (s *Store) ChangePassword(
	ctx context.Context,
	request goauth.PasswordChangeStoreRequest,
) (goauth.PasswordChangeStoreResult, error) {
	if request.SubjectID.IsZero() || request.ExpectedPasswordPHC == "" || request.NewPasswordPHC == "" ||
		request.Now.IsZero() {
		return goauth.PasswordChangeStoreResult{}, errors.New("invalid password change request")
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("begin password change: %w", err)
	}
	defer rollbackWrite(tx, owned)

	var currentPHC, status string
	var retired sql.NullTime
	err = tx.QueryRowContext(ctx, `
	SELECT status,retired_at FROM auth_subjects WHERE id = $1 FOR UPDATE`, request.SubjectID).Scan(&status, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreMissing}, nil
	}
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("lock password change subject: %w", err)
	}
	if retired.Valid {
		return goauth.PasswordChangeStoreResult{}, goauth.ErrSubjectRetired
	}
	err = tx.QueryRowContext(ctx, `
	SELECT password_phc FROM auth_local_credentials WHERE subject_id = $1 FOR UPDATE`,
		request.SubjectID).Scan(&currentPHC)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreMissing}, nil
	}
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, fmt.Errorf("lock password change credential: %w", err)
	}
	if currentPHC != request.ExpectedPasswordPHC {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreConflict}, nil
	}
	if goauth.SubjectStatus(status) != goauth.SubjectStatusActive {
		return goauth.PasswordChangeStoreResult{}, goauth.ErrAccountUnavailable
	}
	updated, err := tx.ExecContext(ctx, `
UPDATE auth_local_credentials
SET password_phc = $2, updated_at = $3, password_input_policy = 'unicode_v1'
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
	if err := invalidatePasswordResets(ctx, tx, request.SubjectID, request.Now); err != nil {
		return goauth.PasswordChangeStoreResult{}, err
	}
	account, err := getAccount(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.PasswordChangeStoreResult{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
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

// accountScanner preserves a genuinely absent email as a zero Identifier.
type accountScanner struct {
	account                         goauth.Account
	status                          string
	id, scheme, display, normalized sql.NullString
	verified, created, updated      sql.NullTime
}

func (s *accountScanner) destinations() []any {
	return []any{
		&s.account.Subject.ID, &s.status, &s.account.Subject.SecurityVersion,
		&s.account.Subject.CreatedAt, &s.account.Subject.UpdatedAt,
		&s.id, &s.scheme, &s.display, &s.normalized, &s.verified, &s.created, &s.updated,
		&s.account.Profile.Username, &s.account.Profile.DisplayName, &s.account.Profile.GivenName, &s.account.Profile.FamilyName,
	}
}

func (s *accountScanner) result() goauth.Account {
	s.account.Subject.Status = goauth.SubjectStatus(s.status)
	if s.id.Valid {
		s.account.PrimaryEmail = goauth.Identifier{
			ID: s.id.String, SubjectID: s.account.Subject.ID,
			Scheme: goauth.IdentifierScheme(s.scheme.String), DisplayValue: s.display.String,
			NormalizedValue: s.normalized.String, CreatedAt: s.created.Time, UpdatedAt: s.updated.Time,
		}
		if s.verified.Valid {
			s.account.PrimaryEmail.VerifiedAt = &s.verified.Time
		}
	}
	return s.account
}

func scanAccount(row scanner) (goauth.Account, error) {
	var scan accountScanner
	if err := row.Scan(scan.destinations()...); err != nil {
		return goauth.Account{}, err
	}
	return scan.result(), nil
}

func scanLocalAccount(row scanner) (goauth.LocalAccountRecord, error) {
	var scan accountScanner
	var record goauth.LocalAccountRecord
	destinations := append(scan.destinations(), &record.PasswordPHC, &record.PasswordInputPolicy)
	if err := row.Scan(destinations...); err != nil {
		return goauth.LocalAccountRecord{}, err
	}
	record.Account = scan.result()
	return record, nil
}

func transformWriteError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%s: %w", operation, goauth.ErrIdentifierAlreadyExists)
	}

	return fmt.Errorf("%s: %w", operation, err)
}

func (s *Store) LockAccount(ctx context.Context, id goauth.SubjectID) (goauth.Account, error) {
	tx, err := s.notificationTx(ctx)
	if err != nil {
		return goauth.Account{}, err
	}
	if tx == nil {
		return goauth.Account{}, errors.New("LockAccount requires AuthTransaction")
	}
	if err := lockSubject(ctx, tx, id); err != nil {
		return goauth.Account{}, err
	}
	return getAccount(ctx, tx, id)
}
