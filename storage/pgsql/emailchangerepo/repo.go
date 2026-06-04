package emailchangerepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	querybuilder "github.com/assurrussa/goshared/pkg/query_builder"
	"github.com/jackc/pgx/v5"

	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/local/emailchange"
)

const tableName = "auth_email_change_requests"

var columns = []string{
	"id",
	"subject_id",
	"old_email",
	"new_email",
	"code",
	"attempts",
	"expires_at",
	"created_at",
	"updated_at",
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
		panic(fmt.Errorf("fatal email change repo: %w", err))
	}

	return repo
}

func (r *Repo) Upsert(ctx context.Context, subjectID string, req emailchange.Request) error {
	const op = "auth.email_changes.Upsert"

	builder := outbox.BuilderDollar().
		Insert(tableName).
		SetMap(querybuilder.Eq{
			"subject_id": subjectID,
			"old_email":  req.OldEmail,
			"new_email":  req.NewEmail,
			"code":       req.Code,
			"attempts":   req.Attempts,
			"expires_at": req.ExpiresAt,
			"created_at": req.CreatedAt,
			"updated_at": req.UpdatedAt,
		}).
		Suffix(`ON CONFLICT (subject_id) DO UPDATE SET
	old_email = EXCLUDED.old_email,
	new_email = EXCLUDED.new_email,
	code = EXCLUDED.code,
	attempts = EXCLUDED.attempts,
	expires_at = EXCLUDED.expires_at,
	updated_at = EXCLUDED.updated_at`)

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) Get(ctx context.Context, subjectID string, forUpdate bool) (emailchange.Request, error) {
	const op = "auth.email_changes.Get"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{"subject_id": subjectID}).
		Limit(1)
	if forUpdate {
		builder = builder.Suffix("FOR UPDATE")
	}

	var row rowModel
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return emailchange.Request{}, emailchange.ErrNotFound
		}
		return emailchange.Request{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return row.toDomain(), nil
}

func (r *Repo) IncrementAttempts(ctx context.Context, subjectID string) error {
	const op = "auth.email_changes.IncrementAttempts"

	builder := outbox.BuilderDollar().
		Update(tableName).
		Set("attempts", squirrel.Expr("attempts + 1")).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"subject_id": subjectID})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) Delete(ctx context.Context, subjectID string) error {
	const op = "auth.email_changes.Delete"

	builder := outbox.BuilderDollar().
		Delete(tableName).
		Where(squirrel.Eq{"subject_id": subjectID})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) CleanupExpired(ctx context.Context, batchSize, minutes int) (int64, error) {
	const op = "auth.email_changes.CleanupExpired"
	if batchSize <= 0 {
		return 0, errors.New("batch size must be positive")
	}
	if minutes < 0 {
		minutes = 0
	}

	query := fmt.Sprintf(`WITH c AS (
  SELECT id FROM %s
  WHERE expires_at < now() - $1 * INTERVAL '1 minute'
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

type rowModel struct {
	ID        int64     `db:"id"`
	SubjectID string    `db:"subject_id"`
	OldEmail  string    `db:"old_email"`
	NewEmail  string    `db:"new_email"`
	Code      string    `db:"code"`
	Attempts  int       `db:"attempts"`
	ExpiresAt time.Time `db:"expires_at"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

func (r rowModel) toDomain() emailchange.Request {
	return emailchange.Request{
		OldEmail:  r.OldEmail,
		NewEmail:  r.NewEmail,
		Code:      r.Code,
		Attempts:  r.Attempts,
		ExpiresAt: r.ExpiresAt,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}
