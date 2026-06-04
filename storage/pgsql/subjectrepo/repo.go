package subjectrepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/jackc/pgx/v5"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/local/confirmation"
	authshared "github.com/assurrussa/goauth/shared"
)

const (
	subjectsTable    = "auth_subjects"
	credentialsTable = "auth_local_credentials"
)

var subjectColumns = []string{
	"s.subject_id",
	"s.kind",
	"s.public_id",
	"s.email",
	"s.username",
	"s.name",
	"s.last_name",
	"s.father_name",
	"s.gender",
	"s.birthday",
	"s.data",
	"s.confirmed_email_at",
	"s.password_version",
	"s.created_at",
	"s.updated_at",
	"lc.password_hash",
}

type Repo struct {
	pgsql outbox.StoragePgsqlClient
	tx    outbox.StoragePgsqlTxManager
}

func New(db outbox.StoragePgsqlClient, tx outbox.StoragePgsqlTxManager) (*Repo, error) {
	if db == nil {
		return nil, errors.New("pgsql client is required")
	}
	if tx == nil {
		return nil, errors.New("tx manager is required")
	}

	return &Repo{pgsql: db, tx: tx}, nil
}

func Must(db outbox.StoragePgsqlClient, tx outbox.StoragePgsqlTxManager) *Repo {
	repo, err := New(db, tx)
	if err != nil {
		panic(fmt.Errorf("fatal subject repo: %w", err))
	}

	return repo
}

func (r *Repo) GetByEmail(ctx context.Context, email string) (authcore.Subject, error) {
	const op = "auth.subjects.GetByEmail"

	builder := outbox.BuilderDollar().
		Select(subjectColumns...).
		From(subjectsTable + " s").
		LeftJoin(credentialsTable + " lc ON lc.subject_id = s.subject_id").
		Where(squirrel.Eq{"s.email": strings.TrimSpace(email)}).
		Limit(1)

	var row subjectRow
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authcore.Subject{}, nil
		}

		return authcore.Subject{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return row.toDomain(), nil
}

func (r *Repo) GetByID(ctx context.Context, subjectID authcore.SubjectID) (authcore.Subject, error) {
	const op = "auth.subjects.GetByID"
	if subjectID.IsZero() {
		return authcore.Subject{}, nil
	}

	builder := outbox.BuilderDollar().
		Select(subjectColumns...).
		From(subjectsTable + " s").
		LeftJoin(credentialsTable + " lc ON lc.subject_id = s.subject_id").
		Where(squirrel.Eq{"s.subject_id": subjectID}).
		Limit(1)

	var row subjectRow
	if err := r.pgsql.DB().Getx(ctx, op, &row, builder); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authcore.Subject{}, nil
		}

		return authcore.Subject{}, fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return row.toDomain(), nil
}

func (r *Repo) CreateUser(ctx context.Context, subject authcore.Subject) (authcore.Subject, error) {
	const op = "auth.subjects.CreateUser"

	email := strings.TrimSpace(subject.Email)
	if email == "" {
		return authcore.Subject{}, errors.New("email is required")
	}

	kind := subject.Kind
	if kind == authcore.SubjectKindUnknown {
		kind = authcore.SubjectKindAccount
	}

	subjectUUID := subject.PublicID
	if subjectUUID.IsZero() {
		subjectUUID = sharedtypes.NewUserID()
	}

	subjectID := subject.ID
	if subjectID.IsZero() {
		subjectID = authshared.NewSubjectID()
	}

	now := time.Now().UTC()
	if err := r.tx.RunInTx(ctx, func(txCtx context.Context) error {
		builder := outbox.BuilderDollar().
			Insert(subjectsTable).
			Columns(
				"subject_id",
				"kind",
				"public_id",
				"email",
				"username",
				"name",
				"last_name",
				"father_name",
				"gender",
				"birthday",
				"data",
				"confirmed_email_at",
				"password_version",
				"created_at",
				"updated_at",
			).
			Values(
				subjectID,
				string(kind),
				subjectUUID,
				email,
				nullableString(subject.Username),
				nullableString(subject.Name),
				nullableString(subject.LastName),
				nullableString(subject.FatherName),
				subject.Gender,
				nullableNullTime(subject.Birthday),
				subject.Data,
				nullableTime(subject.ConfirmedEmailAt),
				subject.PasswordVersion,
				now,
				now,
			)

		if _, err := r.pgsql.DB().Execx(txCtx, op+".insert_subject", builder); err != nil {
			return fmt.Errorf("insert subject: %w", outbox.ErrorTransform(err))
		}

		if subject.PasswordHash == "" {
			return nil
		}

		credBuilder := outbox.BuilderDollar().
			Insert(credentialsTable).
			Columns("subject_id", "password_hash", "created_at", "updated_at").
			Values(subjectID, subject.PasswordHash, now, now)

		if _, err := r.pgsql.DB().Execx(txCtx, op+".insert_credentials", credBuilder); err != nil {
			return fmt.Errorf("insert credentials: %w", outbox.ErrorTransform(err))
		}

		return nil
	}); err != nil {
		return authcore.Subject{}, fmt.Errorf("%s: %w", op, err)
	}

	subject.ID = subjectID
	subject.Kind = kind
	subject.PublicID = subjectUUID
	subject.Email = email
	return subject, nil
}

func (r *Repo) UpdatePassword(ctx context.Context, subject authcore.Subject, passwordHash string) error {
	const op = "auth.subjects.UpdatePassword"

	subjectID := subject.AuthSubjectID()
	if subjectID.IsZero() {
		return errors.New("subject id is required")
	}
	if passwordHash == "" {
		return errors.New("password hash is required")
	}

	now := time.Now().UTC()
	return r.tx.RunInTx(ctx, func(txCtx context.Context) error {
		credBuilder := outbox.BuilderDollar().
			Insert(credentialsTable).
			Columns("subject_id", "password_hash", "created_at", "updated_at").
			Values(subjectID, passwordHash, now, now).
			Suffix(`ON CONFLICT (subject_id)
DO UPDATE SET
	password_hash = EXCLUDED.password_hash,
	updated_at = EXCLUDED.updated_at`)

		if _, err := r.pgsql.DB().Execx(txCtx, op+".upsert_credentials", credBuilder); err != nil {
			return fmt.Errorf("upsert credentials: %w", outbox.ErrorTransform(err))
		}

		subjectBuilder := outbox.BuilderDollar().
			Update(subjectsTable).
			Set("password_version", squirrel.Expr("password_version + 1")).
			Set("updated_at", now).
			Where(squirrel.Eq{"subject_id": subjectID})

		if _, err := r.pgsql.DB().Execx(txCtx, op+".update_subject", subjectBuilder); err != nil {
			return fmt.Errorf("update subject: %w", outbox.ErrorTransform(err))
		}

		return nil
	})
}

func (r *Repo) UpdateEmail(ctx context.Context, subjectID authcore.SubjectID, email string) error {
	const op = "auth.subjects.UpdateEmail"

	email = strings.TrimSpace(email)
	if subjectID.IsZero() {
		return errors.New("subject id is required")
	}
	if email == "" {
		return errors.New("email is required")
	}

	builder := outbox.BuilderDollar().
		Update(subjectsTable).
		Set("email", email).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"subject_id": subjectID})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) MarkEmailConfirmed(ctx context.Context, subjectID authcore.SubjectID, confirmedAt time.Time) error {
	const op = "auth.subjects.MarkEmailConfirmed"

	if subjectID.IsZero() {
		return errors.New("subject id is required")
	}

	builder := outbox.BuilderDollar().
		Update(subjectsTable).
		Set("confirmed_email_at", confirmedAt.UTC()).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"subject_id": subjectID})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) UpdateProfile(ctx context.Context, subjectID authcore.SubjectID, patch authcore.SubjectProfilePatch) error {
	const op = "auth.subjects.UpdateProfile"

	if subjectID.IsZero() {
		return errors.New("subject id is required")
	}

	builder := outbox.BuilderDollar().
		Update(subjectsTable)
	hasChanges := false
	set := func(column string, value any) {
		builder = builder.Set(column, value)
		hasChanges = true
	}

	if patch.Username != nil {
		set("username", nullableString(*patch.Username))
	}
	if patch.Name != nil {
		set("name", nullableString(*patch.Name))
	}
	if patch.LastName != nil {
		set("last_name", nullableString(*patch.LastName))
	}
	if patch.FatherName != nil {
		set("father_name", nullableString(*patch.FatherName))
	}
	if patch.Gender != nil {
		set("gender", *patch.Gender)
	}
	if patch.Birthday != nil {
		set("birthday", nullableNullTime(*patch.Birthday))
	}
	if !hasChanges {
		return nil
	}

	builder = builder.
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"subject_id": subjectID})

	if _, err := r.pgsql.DB().Execx(ctx, op, builder); err != nil {
		return fmt.Errorf("%s: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) ApplyConfirmation(
	ctx context.Context,
	subjectID string,
	confirmationType confirmation.Type,
	confirmedAt time.Time,
) error {
	if confirmationType != confirmation.TypeEmail {
		return nil
	}

	parsedSubjectID, err := authcore.ParseSubjectIDString(subjectID)
	if err != nil {
		return fmt.Errorf("parse subject id: %w", err)
	}

	return r.MarkEmailConfirmed(ctx, parsedSubjectID, confirmedAt)
}

type subjectRow struct {
	SubjectID        authcore.SubjectID    `db:"subject_id"`
	Kind             string                `db:"kind"`
	PublicID         sharedtypes.UserID    `db:"public_id"`
	Email            string                `db:"email"`
	Username         sql.NullString        `db:"username"`
	Name             sql.NullString        `db:"name"`
	LastName         sql.NullString        `db:"last_name"`
	FatherName       sql.NullString        `db:"father_name"`
	Gender           sql.NullInt64         `db:"gender"`
	Birthday         sql.NullTime          `db:"birthday"`
	Data             *authcore.ProfileData `db:"data"`
	ConfirmedEmailAt sql.NullTime          `db:"confirmed_email_at"`
	PasswordVersion  int64                 `db:"password_version"`
	CreatedAt        time.Time             `db:"created_at"`
	UpdatedAt        time.Time             `db:"updated_at"`
	PasswordHash     sql.NullString        `db:"password_hash"`
}

func (r subjectRow) toDomain() authcore.Subject {
	var confirmedEmailAt *time.Time
	if r.ConfirmedEmailAt.Valid {
		tm := r.ConfirmedEmailAt.Time
		confirmedEmailAt = &tm
	}

	subject := authcore.Subject{
		ID:               r.SubjectID,
		Kind:             authcore.SubjectKind(r.Kind),
		PublicID:         r.PublicID,
		Email:            r.Email,
		ConfirmedEmailAt: confirmedEmailAt,
		PasswordVersion:  r.PasswordVersion,
		Birthday:         r.Birthday,
		Data:             r.Data,
		PasswordHash:     r.PasswordHash.String,
	}
	if r.Username.Valid {
		subject.Username = r.Username.String
	}
	if r.Name.Valid {
		subject.Name = r.Name.String
	}
	if r.LastName.Valid {
		subject.LastName = r.LastName.String
	}
	if r.FatherName.Valid {
		subject.FatherName = r.FatherName.String
	}
	if r.Gender.Valid {
		value := int(r.Gender.Int64)
		subject.Gender = &value
	}

	return subject
}

func nullableTime(value *time.Time) any {
	if value == nil || value.IsZero() {
		return nil
	}

	return value.UTC()
}

func nullableString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	return value
}

func nullableNullTime(value sql.NullTime) any {
	if !value.Valid || value.Time.IsZero() {
		return nil
	}

	return value.Time.UTC()
}
