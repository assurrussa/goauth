package confirmationrepo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/internal/legacy/local/confirmation"
	"github.com/assurrussa/goauth/internal/legacy/shared"
)

const tableName = "auth_confirmations"

var columns = []string{
	"id",
	"subject_id", //nolint:goconst // autofix
	"confirmation_type",
	"confirmation_info",
	"purpose",
	"confirmed_at",
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
		panic(fmt.Errorf("fatal confirmation repo: %w", err))
	}

	return repo
}

func (r *Repo) Upsert(ctx context.Context, record confirmation.Record) (int64, error) {
	const op = "auth.confirmations.Upsert"

	builder := outbox.BuilderDollar().
		Insert(tableName).
		Columns(
			"subject_id",
			"confirmation_type",
			"confirmation_info",
			"purpose",
			"confirmed_at",
			"created_at",
			"updated_at",
		).
		Values(
			record.SubjectID,
			record.ConfirmationType.String(),
			record.ConfirmationInfo,
			record.Purpose.String(),
			record.ConfirmedAt,
			record.CreatedAt,
			record.UpdatedAt,
		).
		Suffix(`ON CONFLICT (subject_id, confirmation_type, purpose)
DO UPDATE SET
	confirmation_info = EXCLUDED.confirmation_info,
	confirmed_at = EXCLUDED.confirmed_at,
	updated_at = EXCLUDED.updated_at
RETURNING id`)

	var id int64
	if err := r.pgsql.DB().Getx(ctx, op, &id, builder); err != nil {
		return 0, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return id, nil
}

func (r *Repo) IsConfirmed(
	ctx context.Context,
	subjectID shared.SubjectID,
	confirmationType confirmation.Type,
	purpose confirmation.Purpose,
) (bool, error) {
	const op = "auth.confirmations.IsConfirmed"

	builder := outbox.BuilderDollar().
		Select("COUNT(1) > 0").
		From(tableName).
		Where(squirrel.Eq{
			"subject_id":        subjectID,
			"confirmation_type": confirmationType.String(),
			"purpose":           purpose.String(),
		}).
		Limit(1)

	var confirmed bool
	if err := r.pgsql.DB().ScanOnex(ctx, op, &confirmed, builder); err != nil {
		return false, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return confirmed, nil
}

func (r *Repo) GetConfirmationStatus(ctx context.Context, subjectID shared.SubjectID) (confirmation.Status, error) {
	records, err := r.GetBySubjectID(ctx, subjectID)
	if err != nil {
		return confirmation.Status{}, err
	}

	status := confirmation.Status{}
	for _, record := range records {
		switch record.ConfirmationType {
		case confirmation.TypeEmail:
			status.EmailConfirmed = true
		case confirmation.TypePhone:
			status.PhoneConfirmed = true
		case confirmation.TypeUnknown:
			break
		case confirmation.TypeTgBot:
			status.TelegramConfirmed = true
		}
	}

	return status, nil
}

func (r *Repo) GetBySubjectID(ctx context.Context, subjectID shared.SubjectID) ([]confirmation.Record, error) {
	const op = "auth.confirmations.GetBySubjectID"

	builder := outbox.BuilderDollar().
		Select(columns...).
		From(tableName).
		Where(squirrel.Eq{"subject_id": subjectID}).
		OrderBy("confirmed_at DESC", "id DESC")

	var rows []rowModel
	if err := r.pgsql.DB().Selectx(ctx, op, &rows, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	result := make([]confirmation.Record, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.toDomain())
	}

	return result, nil
}

type rowModel struct {
	ID               int64            `db:"id"`
	SubjectID        shared.SubjectID `db:"subject_id"`
	ConfirmationType string           `db:"confirmation_type"`
	ConfirmationInfo string           `db:"confirmation_info"`
	Purpose          string           `db:"purpose"`
	ConfirmedAt      time.Time        `db:"confirmed_at"`
	CreatedAt        time.Time        `db:"created_at"`
	UpdatedAt        time.Time        `db:"updated_at"`
}

func (r rowModel) toDomain() confirmation.Record {
	return confirmation.Record{
		ID:               r.ID,
		SubjectID:        r.SubjectID,
		ConfirmationType: confirmation.ParseType(r.ConfirmationType),
		ConfirmationInfo: r.ConfirmationInfo,
		Purpose:          confirmation.ParsePurpose(r.Purpose),
		ConfirmedAt:      r.ConfirmedAt,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
}
