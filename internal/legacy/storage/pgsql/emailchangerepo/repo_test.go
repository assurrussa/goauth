//nolint:testpackage // internal test
package emailchangerepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/internal/legacy/local/emailchange"
)

func TestRepoUpsertGetIncrementAndDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 21, 20, 0, 0, time.UTC)
	req := emailchange.Request{
		OldEmail:  "old@example.com",
		NewEmail:  "new@example.com",
		Code:      "123456",
		Attempts:  0,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}

	repo := Must(&fakeClient{
		db: &fakeDB{
			getxFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
				require.Equal(t, "auth.email_changes.Get", op)
				row, ok := dest.(*rowModel)
				require.True(t, ok)
				*row = rowModel{
					ID:        1,
					SubjectID: "123e4567-e89b-12d3-a456-426614174103",
					OldEmail:  req.OldEmail,
					NewEmail:  req.NewEmail,
					Code:      req.Code,
					Attempts:  req.Attempts,
					ExpiresAt: req.ExpiresAt,
					CreatedAt: req.CreatedAt,
					UpdatedAt: req.UpdatedAt,
				}
				return nil
			},
			execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
				switch op {
				case "auth.email_changes.Upsert", "auth.email_changes.IncrementAttempts", "auth.email_changes.Delete":
					return pgconn.NewCommandTag("UPDATE 1"), nil
				default:
					t.Fatalf("unexpected operation %q", op)
					return pgconn.NewCommandTag(""), nil
				}
			},
		},
	})

	subjectID := "123e4567-e89b-12d3-a456-426614174103"

	require.NoError(t, repo.Upsert(ctx, subjectID, req))

	got, err := repo.Get(ctx, subjectID, false)
	require.NoError(t, err)
	require.Equal(t, req.NewEmail, got.NewEmail)

	require.NoError(t, repo.IncrementAttempts(ctx, subjectID))
	require.NoError(t, repo.Delete(ctx, subjectID))
}

type fakeClient struct {
	db *fakeDB
}

func (c *fakeClient) DB() outbox.StoragePgsqlDBEngine { return c.db }
func (c *fakeClient) Close() error                    { return nil }

type fakeDB struct {
	getxFn  func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
}

func (db *fakeDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakeDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakeDB) ScanOnex(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanOnex call")
}

func (db *fakeDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}
func (db *fakeDB) QueryRow(context.Context, string, string, ...any) pgx.Row { return nil }
func (db *fakeDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakeDB) Exec(context.Context, string, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("DELETE 1"), nil
}

func (db *fakeDB) Getx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.getxFn == nil {
		return pgx.ErrNoRows
	}
	return db.getxFn(ctx, op, dest, sqlizer)
}

func (db *fakeDB) Selectx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error { return nil }

func (db *fakeDB) Execx(ctx context.Context, op string, sqlizer outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}
	return db.execxFn(ctx, op, sqlizer)
}

func (db *fakeDB) Queryx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgx.Rows, error) {
	return nil, errors.New("unexpected Queryx call")
}
func (db *fakeDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults { return nil }
func (db *fakeDB) CopyFrom(context.Context, string, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakeDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not implemented")
}
func (db *fakeDB) Ping(context.Context) error { return nil }
func (db *fakeDB) Close()                     {}
func (db *fakeDB) Pool() *pgxpool.Pool        { return nil }

var _ outbox.StoragePgsqlDBEngine = (*fakeDB)(nil)
