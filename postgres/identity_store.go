package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/assurrussa/goauth"
)

func (s *Store) ResolveIdentityLink(
	ctx context.Context,
	issuer string,
	externalSubject string,
) (goauth.Account, goauth.IdentityLink, error) {
	var link goauth.IdentityLink
	err := s.queryer(ctx).QueryRowContext(ctx, `
SELECT id, subject_id, issuer, external_subject, email_normalized, email_verified, created_at, updated_at
FROM auth_identity_links
WHERE issuer = $1 AND external_subject = $2`, issuer, externalSubject).Scan(
		&link.ID,
		&link.SubjectID,
		&link.Issuer,
		&link.ExternalSubject,
		&link.EmailNormalized,
		&link.EmailVerified,
		&link.CreatedAt,
		&link.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.Account{}, goauth.IdentityLink{}, goauth.ErrIdentityLinkNotFound
	}
	if err != nil {
		return goauth.Account{}, goauth.IdentityLink{}, fmt.Errorf("resolve identity link: %w", err)
	}
	account, err := getAccount(ctx, s.queryer(ctx), link.SubjectID)
	if err != nil {
		return goauth.Account{}, goauth.IdentityLink{}, err
	}

	return account, link, nil
}

func (s *Store) CreateSSOAccount(
	ctx context.Context,
	record goauth.SSOAccountRecord,
) (goauth.Account, goauth.IdentityLink, error) {
	account := record.Account
	if account.Subject.IsZero() || account.PrimaryEmail.ID == "" || record.Link.ID == "" {
		return goauth.Account{}, goauth.IdentityLink{}, errors.New("invalid SSO account record")
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.Account{}, goauth.IdentityLink{}, fmt.Errorf("begin SSO account transaction: %w", err)
	}
	defer rollbackWrite(tx, owned)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_subjects (id, status, security_version, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)`,
		account.Subject.ID,
		account.Subject.Status,
		account.Subject.SecurityVersion,
		account.Subject.CreatedAt,
		account.Subject.UpdatedAt,
	); err != nil {
		return goauth.Account{}, goauth.IdentityLink{}, transformIdentityWriteError("insert SSO subject", err)
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
		return goauth.Account{}, goauth.IdentityLink{}, transformIdentityWriteError("insert SSO identifier", err)
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
		return goauth.Account{}, goauth.IdentityLink{}, transformIdentityWriteError("insert SSO profile", err)
	}
	if err := insertIdentityLink(ctx, tx, record.Link); err != nil {
		return goauth.Account{}, goauth.IdentityLink{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.Account{}, goauth.IdentityLink{}, fmt.Errorf("commit SSO account transaction: %w", err)
	}

	return account, record.Link, nil
}

func (s *Store) LinkIdentity(ctx context.Context, link goauth.IdentityLink) (goauth.IdentityLink, error) {
	if err := insertIdentityLink(ctx, s.notificationExecer(ctx), link); err != nil {
		return goauth.IdentityLink{}, err
	}

	return link, nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertIdentityLink(ctx context.Context, db execer, link goauth.IdentityLink) error {
	_, err := db.ExecContext(ctx, `
INSERT INTO auth_identity_links (
    id, subject_id, issuer, external_subject, email_normalized,
    email_verified, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		link.ID,
		link.SubjectID,
		link.Issuer,
		link.ExternalSubject,
		link.EmailNormalized,
		link.EmailVerified,
		link.CreatedAt,
		link.UpdatedAt,
	)
	if err != nil {
		return transformIdentityWriteError("insert identity link", err)
	}

	return nil
}

func transformIdentityWriteError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		if pgErr.ConstraintName == "auth_identity_links_issuer_external_subject_key" {
			return fmt.Errorf("%s: %w", operation, goauth.ErrIdentityLinkConflict)
		}
		return fmt.Errorf("%s: %w", operation, goauth.ErrIdentifierAlreadyExists)
	}

	return fmt.Errorf("%s: %w", operation, err)
}
