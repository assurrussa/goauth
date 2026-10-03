package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/identifierbounds"
)

func (s *Store) GetLocalIdentifier(
	ctx context.Context, subjectID goauth.SubjectID, scheme goauth.IdentifierScheme,
) (goauth.Identifier, error) {
	if subjectID.IsZero() {
		return goauth.Identifier{}, goauth.ErrAccountNotFound
	}
	if err := validateLocalIdentifierScheme(scheme); err != nil {
		return goauth.Identifier{}, err
	}
	if _, err := s.notificationTx(ctx); err != nil {
		return goauth.Identifier{}, err
	}
	return getLocalIdentifier(ctx, s.queryer(ctx), subjectID, scheme, false)
}

func getLocalIdentifier(ctx context.Context, db queryRower, subjectID goauth.SubjectID,
	scheme goauth.IdentifierScheme, lock bool,
) (goauth.Identifier, error) {
	query := `SELECT id, subject_id, scheme, display_value, normalized_value, verified_at, created_at, updated_at
FROM auth_identifiers WHERE subject_id=$1 AND scheme=$2 AND is_primary=true`
	if lock {
		query += ` FOR UPDATE`
	}
	var identifier goauth.Identifier
	var verified sql.NullTime
	err := db.QueryRowContext(ctx, query, subjectID, scheme).Scan(&identifier.ID, &identifier.SubjectID,
		&identifier.Scheme, &identifier.DisplayValue, &identifier.NormalizedValue,
		&verified, &identifier.CreatedAt, &identifier.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.Identifier{}, goauth.ErrLocalIdentifierConflict
	}
	if err != nil {
		return goauth.Identifier{}, fmt.Errorf("read local primary identifier: %w", err)
	}
	if verified.Valid {
		identifier.VerifiedAt = &verified.Time
	}
	return identifier, nil
}

func validateLocalIdentifierScheme(scheme goauth.IdentifierScheme) error {
	if scheme == goauth.IdentifierSchemeEmail {
		return goauth.ErrInvalidIdentifierScheme
	}
	return scheme.Validate()
}

func (s *Store) RenameLocalIdentity(
	ctx context.Context, request goauth.RenameLocalIdentityStoreRequest,
) (goauth.LocalIdentityView, error) {
	if request.SubjectID.IsZero() {
		return goauth.LocalIdentityView{}, goauth.ErrAccountNotFound
	}
	if err := validateLocalIdentifierScheme(request.Scheme); err != nil {
		return goauth.LocalIdentityView{}, err
	}
	if request.ExpectedSecurityVersion < 1 {
		return goauth.LocalIdentityView{}, goauth.ErrSecurityVersionMismatch
	}
	if !identifierbounds.Valid(request.ExpectedNormalizedValue) || !identifierbounds.Valid(request.NewDisplayValue) ||
		!identifierbounds.Valid(request.NewNormalizedValue) {
		return goauth.LocalIdentityView{}, goauth.ErrInvalidIdentifier
	}
	if request.Now.IsZero() {
		return goauth.LocalIdentityView{}, errors.New("rename local identity requires a timestamp")
	}
	started := time.Now()
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.LocalIdentityView{}, fmt.Errorf("begin local identity rename: %w", err)
	}
	defer rollbackWrite(tx, owned)
	version, err := lockUnretiredSubject(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.LocalIdentityView{}, err
	}
	if version != request.ExpectedSecurityVersion {
		return goauth.LocalIdentityView{}, goauth.ErrSecurityVersionMismatch
	}
	identifier, err := getLocalIdentifier(ctx, tx, request.SubjectID, request.Scheme, true)
	if err != nil {
		return goauth.LocalIdentityView{}, err
	}
	var credentialSubject goauth.SubjectID
	err = tx.QueryRowContext(ctx, `SELECT subject_id FROM auth_local_credentials WHERE subject_id=$1 FOR UPDATE`,
		request.SubjectID).Scan(&credentialSubject)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.LocalIdentityView{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.LocalIdentityView{}, fmt.Errorf("lock local identity credential: %w", err)
	}
	if identifier.NormalizedValue != request.ExpectedNormalizedValue {
		return goauth.LocalIdentityView{}, goauth.ErrLocalIdentifierConflict
	}
	if identifier.NormalizedValue == request.NewNormalizedValue && identifier.DisplayValue == request.NewDisplayValue {
		return goauth.LocalIdentityView{}, goauth.ErrIdentifierUnchanged
	}
	if version == math.MaxInt64 {
		return goauth.LocalIdentityView{}, errors.New("local identity security version overflow")
	}
	now := securityTime(ctx, request.Now, started)
	if err := tx.QueryRowContext(ctx, `
UPDATE auth_identifiers SET display_value=$2,normalized_value=$3,updated_at=$4 WHERE id=$1
RETURNING display_value,normalized_value,updated_at`,
		identifier.ID, request.NewDisplayValue, request.NewNormalizedValue, now,
	).Scan(&identifier.DisplayValue, &identifier.NormalizedValue, &identifier.UpdatedAt); err != nil {
		return goauth.LocalIdentityView{}, transformWriteError("rename local identifier", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_subjects SET security_version=security_version+1,updated_at=$2 WHERE id=$1`,
		request.SubjectID, now); err != nil {
		return goauth.LocalIdentityView{}, fmt.Errorf("advance local identity security version: %w", err)
	}
	if _, err := revokeSubjectSecurityState(ctx, tx, request.SubjectID, now); err != nil {
		return goauth.LocalIdentityView{}, err
	}
	if err := invalidatePasswordResets(ctx, tx, request.SubjectID, now); err != nil {
		return goauth.LocalIdentityView{}, err
	}
	account, err := getAccount(ctx, tx, request.SubjectID)
	if err != nil {
		return goauth.LocalIdentityView{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.LocalIdentityView{}, fmt.Errorf("commit local identity rename: %w", err)
	}
	return goauth.LocalIdentityView{Account: account, Identifier: identifier}, nil
}

var (
	_ goauth.LocalIdentifierReader    = (*Store)(nil)
	_ goauth.LocalIdentityRenameStore = (*Store)(nil)
)
