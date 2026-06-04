package sessionrepo

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

const tableName = "auth_sessions"

var columns = []string{
	"id",
	//nolint:goconst // dbcol
	"subject_id",
	"subject_kind",
	//nolint:goconst // dbcol
	"token",
	"payload",
	"password_version",
	"created_at",
	"expires_at",
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
		panic(fmt.Errorf("fatal session repo: %w", err))
	}

	return repo
}

func (r *Repo) Save(ctx context.Context, session authcore.AuthSession, payload []byte) error {
	const op = "auth.sessions.Save"

	token := strings.TrimSpace(session.Token)
	if token == "" {
		return fmt.Errorf("%s: %w", op, errors.New("session token is required"))
	}

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
			"payload",
			"password_version",
			"created_at",
			"expires_at",
			"revoked_at",
		).
		Values(
			session.SubjectID,
			string(kind),
			token,
			payload,
			session.PasswordVersion,
			createdAt,
			session.ExpiresAt,
			session.RevokedAt,
		).
		Suffix(
			`ON CONFLICT (token) DO UPDATE SET
subject_id = EXCLUDED.subject_id,
subject_kind = EXCLUDED.subject_kind,
payload = EXCLUDED.payload,
password_version = EXCLUDED.password_version,
created_at = EXCLUDED.created_at,
expires_at = EXCLUDED.expires_at,
revoked_at = EXCLUDED.revoked_at`,
		)

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) Get(ctx context.Context, token string) (authcore.AuthSession, []byte, error) {
	const op = "auth.sessions.Get"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{"token": strings.TrimSpace(token)}).
		Limit(1)

	var row rowModel
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authcore.AuthSession{}, nil, authcore.ErrSessionNotFound
		}

		return authcore.AuthSession{}, nil, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	session, payload := row.toDomain()
	return session, payload, nil
}

func (r *Repo) Delete(ctx context.Context, token string) error {
	const op = "auth.sessions.Delete"

	builder := outbox.BuilderDollar().
		Delete(tableName).
		Where(squirrel.Eq{"token": strings.TrimSpace(token)})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) DeleteAll(ctx context.Context, subjectID authcore.SubjectID) (int64, error) {
	const op = "auth.sessions.DeleteAll"

	builder := outbox.BuilderDollar().
		Delete(tableName).
		Where(squirrel.Eq{"subject_id": subjectID})

	res, err := r.pgsql.DB().Execx(ctx, op, builder)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return res.RowsAffected(), nil
}

func (r *Repo) DeleteAllExcept(ctx context.Context, subjectID authcore.SubjectID, keepToken string) (int64, error) {
	const op = "auth.sessions.DeleteAllExcept"

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

type rowModel struct {
	ID              int64              `db:"id"`
	SubjectID       authcore.SubjectID `db:"subject_id"`
	SubjectKind     string             `db:"subject_kind"`
	Token           string             `db:"token"`
	Payload         []byte             `db:"payload"`
	PasswordVersion int64              `db:"password_version"`
	CreatedAt       time.Time          `db:"created_at"`
	ExpiresAt       time.Time          `db:"expires_at"`
	RevokedAt       sql.NullTime       `db:"revoked_at"`
}

func (r rowModel) toDomain() (authcore.AuthSession, []byte) {
	var revokedAt *time.Time
	if r.RevokedAt.Valid {
		value := r.RevokedAt.Time
		revokedAt = &value
	}

	payload := append([]byte(nil), r.Payload...)

	return authcore.AuthSession{
		ID:              strconv.FormatInt(r.ID, 10),
		NumericID:       r.ID,
		SubjectID:       r.SubjectID,
		Kind:            authcore.SubjectKind(r.SubjectKind),
		Token:           r.Token,
		PasswordVersion: r.PasswordVersion,
		CreatedAt:       r.CreatedAt,
		ExpiresAt:       r.ExpiresAt,
		RevokedAt:       revokedAt,
	}, payload
}
