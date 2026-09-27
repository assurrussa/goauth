package oidcrefreshtokenrepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	querybuilder "github.com/assurrussa/outbox/shared/query_builder"
	"github.com/jackc/pgx/v5"

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/oidc"
)

const tableName = "auth_oidc_refresh_tokens"

var columns = []string{
	"id",
	"subject_id",
	"client_id",
	"password_version",
	//nolint:goconst // dbcol
	"token",
	"scopes",
	"authenticated_at",
	"expires_at",
	"created_at",
	//nolint:goconst // dbcol
	"revoked_at",
}

func (r *Repo) Save(ctx context.Context, token oidc.RefreshToken) error {
	const op = "oidc.refresh_tokens.Save"

	builder := outbox.BuilderDollar().
		Insert(tableName).
		SetMap(querybuilder.Eq{
			"subject_id":       token.SubjectID,
			"client_id":        token.ClientID,
			"password_version": token.SecurityVersion,
			"token":            token.Token,
			"scopes":           oidc.ScopeString(token.Scopes),
			"authenticated_at": token.AuthenticatedAt,
			"expires_at":       token.ExpiresAt,
		})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) Get(ctx context.Context, token string) (oidc.RefreshToken, error) {
	const op = "oidc.refresh_tokens.Get"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{"token": strings.TrimSpace(token)}).
		Limit(1)

	var model refreshTokenRow
	if err := r.pgsql.DB().Getx(ctx, op, &model, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return oidc.RefreshToken{}, oidc.ErrRefreshTokenNotFound
		}

		return oidc.RefreshToken{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return toDomain(model), nil
}

func (r *Repo) Revoke(ctx context.Context, token string, revokedAt time.Time) error {
	const op = "oidc.refresh_tokens.Revoke"

	builder := outbox.BuilderDollar().
		Update(tableName).
		Set("revoked_at", revokedAt).
		Where(squirrel.Eq{"token": strings.TrimSpace(token)}).
		Where(squirrel.Eq{"revoked_at": nil})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) Rotate(ctx context.Context, currentToken string, next oidc.RefreshToken, revokedAt time.Time) error {
	return r.trxManager.RunInTx(ctx, func(txCtx context.Context) error {
		const revokeOp = "oidc.refresh_tokens.Rotate.revoke"

		revokeBuilder := outbox.BuilderDollar().
			Update(tableName).
			Set("revoked_at", revokedAt).
			Where(squirrel.Eq{"token": strings.TrimSpace(currentToken)}).
			Where(squirrel.Eq{"revoked_at": nil})

		res, err := r.pgsql.DB().Execx(txCtx, revokeOp, revokeBuilder)
		if err != nil {
			return fmt.Errorf("%s: %w", revokeOp, outbox.ErrorTransform(err))
		}
		if res.RowsAffected() == 0 {
			return oidc.ErrRefreshTokenNotFound
		}

		return r.Save(txCtx, next)
	})
}

func (r *Repo) CleanupExpiredTokens(ctx context.Context, batchSize, minutes int) (int64, error) {
	const op = "oidc.refresh_tokens.CleanupExpiredTokens"
	if batchSize <= 0 {
		return 0, fmt.Errorf("%s: invalid batchSize", op)
	}
	if minutes < 0 {
		minutes = 60
	}

	query := fmt.Sprintf(`WITH c AS (
  SELECT id FROM %s
  WHERE expires_at < now() - $1 * INTERVAL '1 minute'
     OR (revoked_at IS NOT NULL AND revoked_at < now() - $1 * INTERVAL '1 minute')
  ORDER BY id ASC
  FOR UPDATE SKIP LOCKED
  LIMIT $2
)
DELETE FROM %s t
USING c
WHERE t.id = c.id;`, tableName, tableName)

	result, err := r.pgsql.DB().Exec(ctx, op, query, minutes, batchSize)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return result.RowsAffected(), nil
}

func toDomain(model refreshTokenRow) oidc.RefreshToken {
	var revokedAt *time.Time
	if model.RevokedAt.Valid {
		revokedAt = &model.RevokedAt.Time
	}

	return oidc.RefreshToken{
		Token:           model.Token,
		SubjectID:       model.SubjectID,
		ClientID:        model.ClientID,
		Scopes:          oidc.ParseScope(model.Scopes),
		SecurityVersion: model.SecurityVersion,
		AuthenticatedAt: model.AuthenticatedAt,
		CreatedAt:       model.CreatedAt,
		ExpiresAt:       model.ExpiresAt,
		RevokedAt:       revokedAt,
	}
}

type refreshTokenRow struct {
	ID              int64        `db:"id"`
	SubjectID       string       `db:"subject_id"`
	ClientID        string       `db:"client_id"`
	SecurityVersion int64        `db:"password_version"`
	Token           string       `db:"token"`
	Scopes          string       `db:"scopes"`
	AuthenticatedAt time.Time    `db:"authenticated_at"`
	ExpiresAt       time.Time    `db:"expires_at"`
	CreatedAt       time.Time    `db:"created_at"`
	RevokedAt       sql.NullTime `db:"revoked_at"`
}
