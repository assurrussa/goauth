//nolint:testpackage // internal test
package subjectrepo

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

func TestRepoCreateUserAndGetByEmail(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var stored authcore.Subject

	db := &fakeSubjectDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			switch op {
			case "auth.subjects.CreateUser.insert_subject", "auth.subjects.CreateUser.insert_credentials":
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			default:
				t.Fatalf("unexpected operation %q", op)
				return pgconn.NewCommandTag(""), nil
			}
		},
		getxFn: func(_ context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
			require.Equal(t, "auth.subjects.GetByEmail", op)
			query, _, err := sqlizer.ToSql()
			require.NoError(t, err)
			require.Contains(t, query, "FROM auth_subjects s")
			require.NotContains(t, query, "FROM users")
			require.NotContains(t, query, "FROM administrations")

			row, ok := dest.(*subjectRow)
			require.True(t, ok)
			*row = subjectRow{
				SubjectID:       stored.ID,
				Kind:            string(stored.Kind),
				PublicID:        stored.PublicID,
				Email:           stored.Email,
				PasswordVersion: stored.PasswordVersion,
				PasswordHash:    sql.NullString{String: stored.PasswordHash, Valid: true},
			}
			return nil
		},
	}

	repo := Must(&fakeSubjectClient{db: db}, &fakeSubjectTxManager{})
	created, err := repo.CreateUser(ctx, authcore.Subject{
		Kind:         authcore.SubjectKindUser,
		Email:        "user@example.com",
		PasswordHash: "hash:secret",
	})
	require.NoError(t, err)
	require.False(t, created.ID.IsZero())
	require.False(t, created.PublicID.IsZero())
	require.NotEqual(t, authcore.SubjectID(created.PublicID), created.ID)

	stored = created
	got, err := repo.GetByEmail(ctx, created.Email)
	require.NoError(t, err)
	require.Equal(t, created.ID, got.ID)
	require.Equal(t, created.PasswordHash, got.PasswordHash)
}

func TestRepoUpdatePassword(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ops := make([]string, 0, 2)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174070")
	tx := &fakeSubjectTxManager{}
	repo := Must(&fakeSubjectClient{
		db: &fakeSubjectDB{
			execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
				ops = append(ops, op)
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}, tx)

	err := repo.UpdatePassword(ctx, authcore.Subject{
		ID:       subjectID,
		Kind:     authcore.SubjectKindUser,
		PublicID: sharedtypes.NewUserID(),
	}, "hash:next")
	require.NoError(t, err)
	require.Equal(t, []string{
		"auth.subjects.UpdatePassword.upsert_credentials",
		"auth.subjects.UpdatePassword.update_subject",
	}, ops)
	require.Equal(t, 1, tx.runInTxCalls)
}

func TestRepoUpdateEmailAndMarkConfirmed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ops := make([]string, 0, 2)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174071")
	repo := Must(&fakeSubjectClient{
		db: &fakeSubjectDB{
			execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
				ops = append(ops, op)
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}, &fakeSubjectTxManager{})

	err := repo.UpdateEmail(ctx, subjectID, "next@example.com")
	require.NoError(t, err)

	err = repo.MarkEmailConfirmed(ctx, subjectID, time.Date(2026, 4, 18, 18, 0, 0, 0, time.UTC))
	require.NoError(t, err)

	require.Equal(t, []string{
		"auth.subjects.UpdateEmail",
		"auth.subjects.MarkEmailConfirmed",
	}, ops)
}

func TestRepoUpdateProfileUpdatesCanonicalProfileFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	username := "next-user"
	name := "Next"
	lastName := "Profile"
	fatherName := "Parent"
	gender := 2
	birthday := sql.NullTime{
		Time:  time.Date(1990, 2, 3, 0, 0, 0, 0, time.UTC),
		Valid: true,
	}
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174072")
	ops := make([]string, 0, 1)
	repo := Must(&fakeSubjectClient{
		db: &fakeSubjectDB{
			execxFn: func(_ context.Context, op string, sqlizer outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
				ops = append(ops, op)
				require.Equal(t, "auth.subjects.UpdateProfile", op)

				query, args, err := sqlizer.ToSql()
				require.NoError(t, err)
				require.Contains(t, query, "UPDATE auth_subjects")
				require.Contains(t, query, "username =")
				require.Contains(t, query, "name =")
				require.Contains(t, query, "last_name =")
				require.Contains(t, query, "father_name =")
				require.Contains(t, query, "gender =")
				require.Contains(t, query, "birthday =")
				require.Contains(t, query, "updated_at =")
				require.Contains(t, query, "WHERE subject_id =")
				require.NotContains(t, query, "email =")
				require.NotContains(t, query, "password")
				require.NotContains(t, query, "confirmed_email_at")
				require.Contains(t, args, subjectID.String())
				require.Contains(t, args, username)
				require.Contains(t, args, name)
				require.Contains(t, args, lastName)
				require.Contains(t, args, fatherName)
				require.Contains(t, args, gender)

				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
		},
	}, &fakeSubjectTxManager{})

	err := repo.UpdateProfile(ctx, subjectID, authcore.SubjectProfilePatch{
		Username:   &username,
		Name:       &name,
		LastName:   &lastName,
		FatherName: &fatherName,
		Gender:     &gender,
		Birthday:   &birthday,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"auth.subjects.UpdateProfile"}, ops)
}

func TestRepoUpdateProfileNoopDoesNotWrite(t *testing.T) {
	t.Parallel()

	repo := Must(&fakeSubjectClient{
		db: &fakeSubjectDB{
			execxFn: func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
				t.Fatal("unexpected Execx call")
				return pgconn.NewCommandTag(""), nil
			},
		},
	}, &fakeSubjectTxManager{})

	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174073")
	err := repo.UpdateProfile(context.Background(), subjectID, authcore.SubjectProfilePatch{})
	require.NoError(t, err)
}

type fakeSubjectClient struct {
	db *fakeSubjectDB
}

func (c *fakeSubjectClient) DB() outbox.StoragePgsqlDBEngine { return c.db }
func (c *fakeSubjectClient) Close() error                    { return nil }

type fakeSubjectTxManager struct {
	runInTxCalls int
}

func (m *fakeSubjectTxManager) RunInTx(ctx context.Context, fn func(context.Context) error) error {
	m.runInTxCalls++
	return fn(ctx)
}

func (*fakeSubjectTxManager) ReadCommitted(context.Context, pgx.TxAccessMode, outbox.StoragePgsqlFnCallback) error {
	return nil
}

func (*fakeSubjectTxManager) RepeatableRead(context.Context, pgx.TxAccessMode, outbox.StoragePgsqlFnCallback) error {
	return nil
}

func (*fakeSubjectTxManager) Serializable(context.Context, pgx.TxAccessMode, outbox.StoragePgsqlFnCallback) error {
	return nil
}

type fakeSubjectDB struct {
	getxFn  func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
}

func (db *fakeSubjectDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakeSubjectDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakeSubjectDB) ScanOnex(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanOnex call")
}

func (db *fakeSubjectDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}
func (db *fakeSubjectDB) QueryRow(context.Context, string, string, ...any) pgx.Row { return nil }
func (db *fakeSubjectDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakeSubjectDB) Exec(context.Context, string, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

func (db *fakeSubjectDB) Getx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.getxFn == nil {
		return pgx.ErrNoRows
	}
	return db.getxFn(ctx, op, dest, sqlizer)
}

func (db *fakeSubjectDB) Selectx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return nil
}

func (db *fakeSubjectDB) Execx(ctx context.Context, op string, sqlizer outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}
	return db.execxFn(ctx, op, sqlizer)
}

func (db *fakeSubjectDB) Queryx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgx.Rows, error) {
	return nil, errors.New("unexpected Queryx call")
}
func (db *fakeSubjectDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults { return nil }
func (db *fakeSubjectDB) CopyFrom(context.Context, string, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakeSubjectDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not implemented")
}
func (db *fakeSubjectDB) Ping(context.Context) error { return nil }
func (db *fakeSubjectDB) Close()                     {}
func (db *fakeSubjectDB) Pool() *pgxpool.Pool        { return nil }

var _ outbox.StoragePgsqlDBEngine = (*fakeSubjectDB)(nil)
