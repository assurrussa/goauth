package identitylinkrepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/sso"
)

const tableName = "auth_sso_identity_links"

var columns = []string{
	"subject_id", //nolint:goconst // autofix
	"subject_kind",
	"issuer",           //nolint:goconst // autofix
	"external_subject", //nolint:goconst // autofix
	"auth_source",
	"email",
	"email_verified",
	"last_seen_at",
	"created_at",
	"updated_at",
}

func (r *Repo) GetByExternalSubject(ctx context.Context, issuer, externalSub string) (sso.IdentityLink, error) {
	const op = "sso.identity_links.GetByExternalSubject"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{
			"issuer":           strings.TrimSpace(issuer),
			"external_subject": strings.TrimSpace(externalSub),
		}).
		Limit(1)

	var row rowModel
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sso.IdentityLink{}, sso.ErrIdentityLinkNotFound
		}

		return sso.IdentityLink{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return row.toDomain(), nil
}

func (r *Repo) ListBySubject(ctx context.Context, subjectID authcore.SubjectID) ([]sso.IdentityLink, error) {
	const op = "sso.identity_links.ListBySubject"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{"subject_id": subjectID}).
		OrderBy("created_at ASC")

	var rows []rowModel
	if err := r.pgsql.DB().Selectx(ctx, op, &rows, builder); err != nil {
		return nil, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	result := make([]sso.IdentityLink, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.toDomain())
	}

	return result, nil
}

func (r *Repo) Upsert(ctx context.Context, link sso.IdentityLink) error {
	const op = "sso.identity_links.Upsert"

	builder := outbox.BuilderDollar().
		Insert(tableName).
		Columns(
			"subject_id",
			"subject_kind",
			"issuer",
			"external_subject",
			"auth_source",
			"email",
			"email_verified",
			"last_seen_at",
			"created_at",
			"updated_at",
		).
		Values(
			link.SubjectID,
			string(link.SubjectKind),
			link.Issuer,
			link.ExternalSub,
			string(sso.NormalizeAuthSource(link.AuthSource)),
			nullableString(link.Email),
			nullableBool(link.EmailVerified),
			link.LastSeenAt,
			link.CreatedAt,
			link.UpdatedAt,
		).
		Suffix(`ON CONFLICT (issuer, external_subject)
DO UPDATE SET
	subject_id = EXCLUDED.subject_id,
	subject_kind = EXCLUDED.subject_kind,
	auth_source = EXCLUDED.auth_source,
	email = EXCLUDED.email,
	email_verified = EXCLUDED.email_verified,
	last_seen_at = EXCLUDED.last_seen_at,
	updated_at = EXCLUDED.updated_at`)

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) Delete(ctx context.Context, subjectID authcore.SubjectID, issuer, externalSub string) error {
	const op = "sso.identity_links.Delete"

	builder := outbox.BuilderDollar().
		Delete(tableName).
		Where(squirrel.Eq{
			"subject_id":       subjectID,
			"issuer":           strings.TrimSpace(issuer),
			"external_subject": strings.TrimSpace(externalSub),
		})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

type rowModel struct {
	SubjectID     authcore.SubjectID `db:"subject_id"`
	SubjectKind   string             `db:"subject_kind"`
	Issuer        string             `db:"issuer"`
	ExternalSub   string             `db:"external_subject"`
	AuthSource    string             `db:"auth_source"`
	Email         sql.NullString     `db:"email"`
	EmailVerified sql.NullBool       `db:"email_verified"`
	LastSeenAt    time.Time          `db:"last_seen_at"`
	CreatedAt     time.Time          `db:"created_at"`
	UpdatedAt     time.Time          `db:"updated_at"`
}

func (r rowModel) toDomain() sso.IdentityLink {
	var emailVerified *bool
	if r.EmailVerified.Valid {
		value := r.EmailVerified.Bool
		emailVerified = &value
	}

	return sso.IdentityLink{
		SubjectID:     r.SubjectID,
		SubjectKind:   authcore.SubjectKind(r.SubjectKind),
		Issuer:        r.Issuer,
		ExternalSub:   r.ExternalSub,
		AuthSource:    sso.NormalizeAuthSource(sso.AuthSource(r.AuthSource)),
		Email:         r.Email.String,
		EmailVerified: emailVerified,
		LastSeenAt:    r.LastSeenAt,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	return value
}

func nullableBool(value *bool) any {
	if value == nil {
		return nil
	}

	return *value
}
