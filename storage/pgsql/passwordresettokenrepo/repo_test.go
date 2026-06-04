package passwordresettokenrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

func TestRepoUpsertAndGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	token := authcore.PasswordResetToken{
		Email:     "user@example.com",
		SubjectID: authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174040"),
		Token:     "reset-1",
		CreatedAt: time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC),
	}
	stored := token

	repo := Must(&fakePasswordResetClient{
		db: &fakePasswordResetDB{
			execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
				require.Equal(t, "auth.password_reset_tokens.Upsert", op)
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			},
			getxFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
				require.Equal(t, "auth.password_reset_tokens.GetByEmail", op)
				record, ok := dest.(*authcore.PasswordResetToken)
				require.True(t, ok)
				*record = stored
				return nil
			},
		},
	})

	require.NoError(t, repo.Upsert(ctx, token))
	got, err := repo.GetByEmail(ctx, token.Email)
	require.NoError(t, err)
	require.Equal(t, token.Token, got.Token)
}

type fakePasswordResetClient struct {
	db *fakePasswordResetDB
}

func (c *fakePasswordResetClient) DB() outbox.StoragePgsqlDBEngine { return c.db }
func (c *fakePasswordResetClient) Close() error                    { return nil }

type fakePasswordResetDB struct {
	getxFn  func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
}

func (db *fakePasswordResetDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakePasswordResetDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakePasswordResetDB) ScanOnex(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanOnex call")
}

func (db *fakePasswordResetDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}
func (db *fakePasswordResetDB) QueryRow(context.Context, string, string, ...any) pgx.Row { return nil }
func (db *fakePasswordResetDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakePasswordResetDB) Exec(context.Context, string, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

func (db *fakePasswordResetDB) Getx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.getxFn == nil {
		return pgx.ErrNoRows
	}
	return db.getxFn(ctx, op, dest, sqlizer)
}

func (db *fakePasswordResetDB) Selectx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return nil
}

func (db *fakePasswordResetDB) Execx(ctx context.Context, op string, sqlizer outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}
	return db.execxFn(ctx, op, sqlizer)
}

func (db *fakePasswordResetDB) Queryx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgx.Rows, error) {
	return nil, errors.New("unexpected Queryx call")
}

func (db *fakePasswordResetDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (db *fakePasswordResetDB) CopyFrom(context.Context, string, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakePasswordResetDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, nil
}
func (db *fakePasswordResetDB) Ping(context.Context) error { return nil }
func (db *fakePasswordResetDB) Close()                     {}
func (db *fakePasswordResetDB) Pool() *pgxpool.Pool        { return nil }

var _ outbox.StoragePgsqlDBEngine = (*fakePasswordResetDB)(nil)
