package confirmationcoderepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/local/confirmation"
	"github.com/assurrussa/goauth/shared"
)

const tableName = "auth_confirmation_codes"

var columns = []string{
	"id",
	"subject_id", //nolint:goconst // autofix
	"code",
	"confirmation_type", //nolint:goconst // autofix
	"confirmation_info",
	"purpose",
	"attempts",
	"verified_at",
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
		panic(fmt.Errorf("fatal confirmation code repo: %w", err))
	}

	return repo
}

func (r *Repo) UpsertCode(ctx context.Context, record confirmation.CodeRecord) (int64, error) {
	const op = "auth.confirmation_codes.UpsertCode"

	builder := outbox.BuilderDollar().
		Insert(tableName).
		Columns(
			"subject_id",
			"code",
			"confirmation_type",
			"confirmation_info",
			"purpose",
			"attempts",
			"verified_at",
			"expires_at",
			"created_at",
			"updated_at",
		).
		Values(
			record.SubjectID,
			record.Code.String(),
			record.ConfirmationType.String(),
			record.ConfirmationInfo,
			record.Purpose.String(),
			record.Attempts,
			nullableTime(record.VerifiedAt),
			record.ExpiresAt,
			record.CreatedAt,
			record.UpdatedAt,
		).
		Suffix(`ON CONFLICT (subject_id, confirmation_type, purpose)
DO UPDATE SET
	code = EXCLUDED.code,
	confirmation_info = EXCLUDED.confirmation_info,
	attempts = EXCLUDED.attempts,
	verified_at = EXCLUDED.verified_at,
	expires_at = EXCLUDED.expires_at,
	updated_at = EXCLUDED.updated_at
RETURNING id`)

	var id int64
	if err := r.pgsql.DB().Getx(ctx, op, &id, builder); err != nil {
		return 0, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return id, nil
}

func (r *Repo) GetActiveCodeBySubjectAndType(
	ctx context.Context,
	subjectID shared.SubjectID,
	codeType confirmation.Type,
	purpose confirmation.Purpose,
) (confirmation.CodeRecord, error) {
	const op = "auth.confirmation_codes.GetActiveCodeBySubjectAndType"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{
			"subject_id":        subjectID,
			"confirmation_type": codeType.String(),
			"purpose":           purpose.String(),
		}).
		Suffix("FOR UPDATE").
		Limit(1)

	var row rowModel
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return confirmation.CodeRecord{}, confirmation.ErrCodeNotFound
		}
		return confirmation.CodeRecord{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return row.toDomain(), nil
}

func (r *Repo) UpdateVerified(ctx context.Context, record confirmation.CodeRecord) error {
	const op = "auth.confirmation_codes.UpdateVerified"

	builder := outbox.BuilderDollar().
		Update(tableName).
		Set("verified_at", nullableTime(record.VerifiedAt)).
		Set("updated_at", record.UpdatedAt).
		Where(squirrel.Eq{"id": record.ID})

	res, err := r.pgsql.DB().Execx(ctx, op, builder)
	if err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}
	if res.RowsAffected() == 0 {
		return confirmation.ErrCodeNotFound
	}

	return nil
}

func (r *Repo) IncrementAttempts(ctx context.Context, id int64) error {
	const op = "auth.confirmation_codes.IncrementAttempts"

	builder := outbox.BuilderDollar().
		Update(tableName).
		Set("attempts", squirrel.Expr("attempts + 1")).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id})

	res, err := r.pgsql.DB().Execx(ctx, op, builder)
	if err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}
	if res.RowsAffected() == 0 {
		return confirmation.ErrCodeNotFound
	}

	return nil
}

func (r *Repo) FindLast(
	ctx context.Context,
	subjectID shared.SubjectID,
	targetType confirmation.Type,
) (*confirmation.CodeRecord, error) {
	const op = "auth.confirmation_codes.FindLast"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{
			"subject_id":        subjectID,
			"confirmation_type": targetType.String(),
		}).
		OrderBy("created_at DESC").
		Limit(1)

	var row rowModel
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, confirmation.ErrCodeNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	record := row.toDomain()
	return &record, nil
}

func (r *Repo) CountSince(
	ctx context.Context,
	subjectID shared.SubjectID,
	targetType confirmation.Type,
	since time.Time,
) (confirmation.UsageWindow, error) {
	const op = "auth.confirmation_codes.CountSince"

	builder := outbox.BuilderDollar().
		Select(`
		COUNT(*) FILTER (WHERE acc.created_at >= const.ts - interval '1 hour')  AS last_hour,
		COUNT(*) FILTER (WHERE acc.created_at >= const.ts - interval '24 hour') AS last_24h
	`).
		Prefix("WITH const AS (SELECT ?::timestamptz AS ts)", since).
		From(tableName + " acc").
		Join("const ON true").
		Where(squirrel.Eq{
			"subject_id":        subjectID,
			"confirmation_type": targetType.String(),
		}).
		Where(squirrel.Expr("acc.created_at >= const.ts - interval '24 hour'"))

	var data usageWindowModel
	if err := r.pgsql.DB().ScanOnex(ctx, op, &data, builder); err != nil {
		return confirmation.UsageWindow{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return confirmation.UsageWindow{
		LastHour: data.LastHour,
		Last24h:  data.Last24h,
	}, nil
}

func (r *Repo) CleanupExpiredCodes(ctx context.Context, batchSize, minutes int) (int64, error) {
	const op = "auth.confirmation_codes.CleanupExpiredCodes"
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
	ID               int64            `db:"id"`
	SubjectID        shared.SubjectID `db:"subject_id"`
	Code             string           `db:"code"`
	ConfirmationType string           `db:"confirmation_type"`
	ConfirmationInfo string           `db:"confirmation_info"`
	Purpose          string           `db:"purpose"`
	Attempts         int              `db:"attempts"`
	VerifiedAt       sql.NullTime     `db:"verified_at"`
	ExpiresAt        time.Time        `db:"expires_at"`
	CreatedAt        time.Time        `db:"created_at"`
	UpdatedAt        time.Time        `db:"updated_at"`
}

func (r rowModel) toDomain() confirmation.CodeRecord {
	return confirmation.CodeRecord{
		ID:               r.ID,
		SubjectID:        r.SubjectID,
		Code:             confirmation.Code(r.Code),
		ConfirmationType: confirmation.ParseType(r.ConfirmationType),
		ConfirmationInfo: r.ConfirmationInfo,
		Purpose:          confirmation.ParsePurpose(r.Purpose),
		Attempts:         r.Attempts,
		VerifiedAt:       pointerTime(r.VerifiedAt),
		ExpiresAt:        r.ExpiresAt,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
}

type usageWindowModel struct {
	LastHour int `db:"last_hour"`
	Last24h  int `db:"last_24h"`
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}

func pointerTime(value sql.NullTime) *time.Time {
	if !value.Valid || value.Time.IsZero() {
		return nil
	}
	tm := value.Time
	return &tm
}
