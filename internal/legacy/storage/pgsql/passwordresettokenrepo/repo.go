package passwordresettokenrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

const tableName = "auth_password_reset_tokens"

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
		panic(fmt.Errorf("fatal password reset token repo: %w", err))
	}

	return repo
}

func (r *Repo) Upsert(ctx context.Context, token authcore.PasswordResetToken) error {
	const op = "auth.password_reset_tokens.Upsert"

	builder := outbox.BuilderDollar().
		Insert(tableName).
		Columns("email", "subject_id", "token", "created_at").
		Values(token.Email, token.SubjectID, token.Token, token.CreatedAt).
		Suffix(`ON CONFLICT (email)
DO UPDATE SET
	subject_id = EXCLUDED.subject_id,
	token = EXCLUDED.token,
	created_at = EXCLUDED.created_at`)

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) GetByEmail(ctx context.Context, email string) (authcore.PasswordResetToken, error) {
	const op = "auth.password_reset_tokens.GetByEmail"

	builder := outbox.BuilderDollar().
		Select("email", "subject_id", "token", "created_at").
		From(tableName).
		Where(squirrel.Eq{"email": strings.TrimSpace(email)}).
		Limit(1)

	var token authcore.PasswordResetToken
	if err := r.pgsql.DB().Getx(ctx, op, &token, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authcore.PasswordResetToken{}, nil
		}

		return authcore.PasswordResetToken{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return token, nil
}

func (r *Repo) DeleteByEmail(ctx context.Context, email string) error {
	const op = "auth.password_reset_tokens.DeleteByEmail"

	builder := outbox.BuilderDollar().
		Delete(tableName).
		Where(squirrel.Eq{"email": strings.TrimSpace(email)})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}
