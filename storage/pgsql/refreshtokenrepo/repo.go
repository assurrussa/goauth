package refreshtokenrepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

const tableName = "auth_refresh_tokens"

var columns = []string{
	"id",
	"subject_id", //nolint:goconst // autofix
	"subject_kind",
	"token", //nolint:goconst // autofix
	"password_version",
	"reason",
	"banned_at",
	"expires_at",
	"created_at",
	"revoked_at",
}

type Repo struct {
	pgsql outbox.StoragePgsqlClient
}

func New(db outbox.StoragePgsqlClient) (*Repo, error) {
	if db == nil {
		return nil, errors.New("pgsql client is required")
	}

	return &Repo{pgsql: db}, nil
}

func Must(db outbox.StoragePgsqlClient) *Repo {
	repo, err := New(db)
	if err != nil {
		panic(fmt.Errorf("fatal refresh token repo: %w", err))
	}

	return repo
}

func (r *Repo) Save(ctx context.Context, session authcore.AuthSession) error {
	const op = "auth.refresh_tokens.Save"

	kind := session.Kind
	if kind == authcore.SubjectKindUnknown {
		kind = authcore.SubjectKindAccount
	}
	createdAt := session.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	builder := outbox.BuilderDollar().
		Insert(tableName).
		Columns(
			"subject_id",
			"subject_kind",
			"token",
			"password_version",
			"reason",
			"banned_at",
			"expires_at",
			"created_at",
			"revoked_at",
		).
		Values(
			session.SubjectID,
			string(kind),
			session.Token,
			session.PasswordVersion,
			session.Reason,
			session.BannedAt,
			session.ExpiresAt,
			createdAt,
			session.RevokedAt,
		)

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) Get(ctx context.Context, token string) (authcore.AuthSession, error) {
	return r.getOne(ctx, "auth.refresh_tokens.Get", squirrel.Eq{"token": strings.TrimSpace(token)})
}

func (r *Repo) GetBySessionID(ctx context.Context, sessionID int64) (authcore.AuthSession, error) {
	return r.getOne(ctx, "auth.refresh_tokens.GetBySessionID", squirrel.Eq{"id": sessionID})
}

func (r *Repo) ListBySubject(ctx context.Context, subjectID authcore.SubjectID) ([]authcore.AuthSession, error) {
	const op = "auth.refresh_tokens.ListBySubject"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{"subject_id": subjectID}).
		OrderBy("created_at DESC")

	var rows []rowModel
	if err := r.pgsql.DB().Selectx(ctx, op, &rows, builder); err != nil {
		return nil, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	result := make([]authcore.AuthSession, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.toDomain())
	}

	return result, nil
}

func (r *Repo) Delete(ctx context.Context, subjectID authcore.SubjectID, token string) (bool, error) {
	return r.delete(ctx, "auth.refresh_tokens.Delete", squirrel.Eq{
		"subject_id": subjectID,
		"token":      strings.TrimSpace(token),
	})
}

func (r *Repo) DeleteAll(ctx context.Context, subjectID authcore.SubjectID) (int64, error) {
	return r.deleteCount(ctx, "auth.refresh_tokens.DeleteAll", squirrel.Eq{
		"subject_id": subjectID,
	})
}

func (r *Repo) DeleteAllExcept(ctx context.Context, subjectID authcore.SubjectID, keepToken string) (int64, error) {
	const op = "auth.refresh_tokens.DeleteAllExcept"

	builder := outbox.BuilderDollar().
		Delete(tableName).
		Where(squirrel.Eq{"subject_id": subjectID}).
		Where(squirrel.NotEq{"token": strings.TrimSpace(keepToken)})

	res, err := r.pgsql.DB().Execx(ctx, op, builder)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return res.RowsAffected(), nil
}

func (r *Repo) DeleteBySessionID(ctx context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error) {
	return r.delete(ctx, "auth.refresh_tokens.DeleteBySessionID", squirrel.Eq{
		"subject_id": subjectID,
		"id":         sessionID,
	})
}

func (r *Repo) Ban(ctx context.Context, subjectID authcore.SubjectID, sessionID int64, reason string) (bool, error) {
	const op = "auth.refresh_tokens.Ban"

	builder := outbox.BuilderDollar().
		Update(tableName).
		Set("reason", strings.TrimSpace(reason)).
		Set("banned_at", time.Now().UTC()).
		Where(squirrel.Eq{
			"subject_id": subjectID,
			"id":         sessionID,
		})

	res, err := r.pgsql.DB().Execx(ctx, op, builder)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return res.RowsAffected() > 0, nil
}

func (r *Repo) Unban(ctx context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error) {
	const op = "auth.refresh_tokens.Unban"

	builder := outbox.BuilderDollar().
		Update(tableName).
		Set("reason", nil).
		Set("banned_at", nil).
		Where(squirrel.Eq{
			"subject_id": subjectID,
			"id":         sessionID,
		})

	res, err := r.pgsql.DB().Execx(ctx, op, builder)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return res.RowsAffected() > 0, nil
}

func (r *Repo) IsBanned(ctx context.Context, token string) (bool, error) {
	session, err := r.Get(ctx, token)
	if err != nil {
		if errors.Is(err, authcore.ErrSessionNotFound) {
			return false, nil
		}
		return false, err
	}

	return session.BannedAt != nil, nil
}

func (r *Repo) getOne(ctx context.Context, op string, where squirrel.Eq) (authcore.AuthSession, error) {
	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(where).
		Limit(1)

	var row rowModel
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authcore.AuthSession{}, authcore.ErrSessionNotFound
		}

		return authcore.AuthSession{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return row.toDomain(), nil
}

func (r *Repo) delete(ctx context.Context, op string, where squirrel.Eq) (bool, error) {
	count, err := r.deleteCount(ctx, op, where)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *Repo) deleteCount(ctx context.Context, op string, where squirrel.Eq) (int64, error) {
	builder := outbox.BuilderDollar().
		Delete(tableName).
		Where(where)

	res, err := r.pgsql.DB().Execx(ctx, op, builder)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return res.RowsAffected(), nil
}

type rowModel struct {
	ID              int64              `db:"id"`
	SubjectID       authcore.SubjectID `db:"subject_id"`
	SubjectKind     string             `db:"subject_kind"`
	Token           string             `db:"token"`
	PasswordVersion int64              `db:"password_version"`
	Reason          sql.NullString     `db:"reason"`
	BannedAt        sql.NullTime       `db:"banned_at"`
	ExpiresAt       time.Time          `db:"expires_at"`
	CreatedAt       time.Time          `db:"created_at"`
	RevokedAt       sql.NullTime       `db:"revoked_at"`
}

func (r rowModel) toDomain() authcore.AuthSession {
	var reason *string
	if r.Reason.Valid {
		value := r.Reason.String
		reason = &value
	}
	var bannedAt *time.Time
	if r.BannedAt.Valid {
		value := r.BannedAt.Time
		bannedAt = &value
	}
	var revokedAt *time.Time
	if r.RevokedAt.Valid {
		value := r.RevokedAt.Time
		revokedAt = &value
	}

	return authcore.AuthSession{
		ID:              strconv.FormatInt(r.ID, 10),
		NumericID:       r.ID,
		SubjectID:       r.SubjectID,
		Kind:            authcore.SubjectKind(r.SubjectKind),
		Token:           r.Token,
		PasswordVersion: r.PasswordVersion,
		Reason:          reason,
		BannedAt:        bannedAt,
		CreatedAt:       r.CreatedAt,
		ExpiresAt:       r.ExpiresAt,
		RevokedAt:       revokedAt,
	}
}
